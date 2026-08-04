/*
Copyright The Athenz Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package driver

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"syscall"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
)

const (
	// WriteModeInPlace rewrites the contents of the existing files in the
	// volume's data directory, never replacing the files themselves. Consumers
	// such as istio-agent watch the certificate file with raw inotify, which
	// binds to the file's inode: replacing the file (as the csi-lib atomic
	// writer does, and as a temp-file + rename would too) unlinks that inode,
	// the kernel tears the watch down, and the consumer keeps serving a stale
	// certificate until it expires.
	WriteModeInPlace = "in-place"

	// WriteModeAtomicDir is the upstream csi-lib behaviour: every write creates
	// a new timestamped directory, re-points the `..data` symlink and deletes
	// the previous directory. Kept only as a rollback path.
	WriteModeAtomicDir = "atomic-dir"
)

const (
	// inplaceDataDirMode matches the data directory mode used by csi-lib: read
	// and execute only for the fs user and group.
	inplaceDataDirMode os.FileMode = 0550

	// inplaceDataFileMode matches the file mode used by csi-lib for projected
	// certificate data: read only for the owner and group.
	inplaceDataFileMode os.FileMode = 0440
)

// innerStore is the subset of the csi-lib file system storage that
// inplaceWriteStorage delegates to. *storage.Filesystem satisfies it. It is an
// interface rather than the concrete type so the writer can be unit tested:
// storage.NewFilesystem mounts a tmpfs and the fields needed to build a
// *storage.Filesystem by hand are unexported.
type innerStore interface {
	storage.Interface

	// ReadFile is not part of storage.Interface but is required by camanager.
	ReadFile(volumeID, name string) ([]byte, error)
}

// inplaceWriteStorage decorates the csi-lib file system storage, replacing its
// atomic (timestamped directory) writer with one that rewrites file contents in
// place. Every other operation is delegated untouched.
type inplaceWriteStorage struct {
	inner innerStore

	// certFileName is the name of the certificate file, which is written last.
	certFileName string

	// fsGroupVolumeAttributeKey mirrors Filesystem.FSGroupVolumeAttributeKey.
	// It is copied at construction, so the inner store's key must already be
	// set when the wrapper is built.
	fsGroupVolumeAttributeKey string
}

var _ storage.Interface = &inplaceWriteStorage{}

// newInplaceWriteStorage wraps inner so that certificate data is rewritten in
// place instead of through csi-lib's atomic writer.
func newInplaceWriteStorage(inner *storage.Filesystem, certFileName string) *inplaceWriteStorage {
	return &inplaceWriteStorage{
		inner:                     inner,
		certFileName:              certFileName,
		fsGroupVolumeAttributeKey: inner.FSGroupVolumeAttributeKey,
	}
}

func (s *inplaceWriteStorage) PathForVolume(volumeID string) string {
	return s.inner.PathForVolume(volumeID)
}

func (s *inplaceWriteStorage) RemoveVolume(volumeID string) error {
	return s.inner.RemoveVolume(volumeID)
}

func (s *inplaceWriteStorage) ReadMetadata(volumeID string) (metadata.Metadata, error) {
	return s.inner.ReadMetadata(volumeID)
}

func (s *inplaceWriteStorage) ListVolumes() ([]string, error) {
	return s.inner.ListVolumes()
}

func (s *inplaceWriteStorage) WriteMetadata(volumeID string, meta metadata.Metadata) error {
	return s.inner.WriteMetadata(volumeID, meta)
}

func (s *inplaceWriteStorage) RegisterMetadata(meta metadata.Metadata) (bool, error) {
	return s.inner.RegisterMetadata(meta)
}

func (s *inplaceWriteStorage) ReadFile(volumeID, name string) ([]byte, error) {
	return s.inner.ReadFile(volumeID, name)
}

// WriteFiles writes the given data into the volume's data directory, rewriting
// the contents of any file that already exists rather than replacing it.
//
// Nothing in this path deletes, renames or symlinks: the inode a mounted pod
// has open (and has an inotify watch on) must survive every write. When the
// volume was previously written by the csi-lib atomic writer the data directory
// still holds the `..data` symlink layout; opening `<data>/tls.crt` follows that
// chain and rewrites the file inside the timestamped directory, which is exactly
// what we want - the layout is left alone and live pods keep working.
func (s *inplaceWriteStorage) WriteFiles(meta metadata.Metadata, files map[string][]byte) error {
	dataPath := s.inner.PathForVolume(meta.VolumeID)
	if err := os.MkdirAll(dataPath, inplaceDataDirMode); err != nil {
		return fmt.Errorf("ensuring data directory %q: %w", dataPath, err)
	}

	fsGroup, err := s.fsGroupForMetadata(meta)
	if err != nil {
		return err
	}

	if err := ensureDataDirGroup(dataPath, fsGroup); err != nil {
		return err
	}

	// A half-torn-down atomic-writer layout (a `..data` chain pointing at a
	// timestamped directory that no longer exists) can never be repaired by
	// writing through it. Any watch on the old inodes is already dead at that
	// point, so rebuilding the layout with the inner atomic writer cannot break
	// a live consumer - and it is the only way to make the volume writable
	// again.
	broken, err := anyDanglingSymlink(dataPath, files)
	if err != nil {
		return err
	}
	if broken {
		return s.inner.WriteFiles(meta, files)
	}

	for _, name := range orderedWriteNames(files, s.certFileName) {
		if err := writeFileInPlace(filepath.Join(dataPath, name), files[name], fsGroup); err != nil {
			return fmt.Errorf("writing file %q: %w", name, err)
		}
	}

	return nil
}

// orderedWriteNames returns the file names to write, all names sorted
// alphabetically followed by certFileName.
//
// The order is part of the contract with the consumer: istio-agent watches only
// the certificate file, assuming the private key cannot change without the
// certificate changing too. Writing the certificate last means the single event
// it does receive fires when the key, CA bundle and keystores on disk are
// already the matching set.
func orderedWriteNames(files map[string][]byte, certFileName string) []string {
	names := make([]string, 0, len(files))
	for name := range files {
		if name == certFileName {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	if _, ok := files[certFileName]; ok {
		names = append(names, certFileName)
	}

	return names
}

// anyDanglingSymlink reports whether any of the files about to be written
// currently exists as a symlink whose chain no longer resolves to a real file.
func anyDanglingSymlink(dataPath string, files map[string][]byte) (bool, error) {
	for name := range files {
		target := filepath.Join(dataPath, name)

		info, err := os.Lstat(target)
		if errors.Is(err, os.ErrNotExist) {
			// Nothing there yet: a plain create, not a broken chain.
			continue
		}
		if err != nil {
			return false, fmt.Errorf("checking %q for a dangling symlink: %w", name, err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			continue
		}

		if _, err := os.Stat(target); errors.Is(err, os.ErrNotExist) {
			return true, nil
		} else if err != nil {
			return false, fmt.Errorf("resolving symlink %q: %w", name, err)
		}
	}

	return false, nil
}

// writeFileInPlace overwrites the contents of target, following any symlink
// chain, without ever unlinking the file the pod is reading.
func writeFileInPlace(target string, data []byte, fsGroup *int64) error {
	// Lstat before opening so we can tell a file we are creating from one that
	// already exists. Only a freshly created file needs its mode and group
	// ownership set: re-applying them on every write is pure metadata churn
	// that wakes every watcher with an IN_ATTRIB event for no reason.
	_, err := os.Lstat(target)
	created := errors.Is(err, os.ErrNotExist)
	if err != nil && !created {
		return fmt.Errorf("checking existing file: %w", err)
	}

	// Skip identical content, as the csi-lib atomic writer does. camanager
	// rewrites every file on each trust-bundle update even when nothing
	// changed; rewriting the same bytes would wake the pod's watcher for a
	// no-op reload. A read error simply falls through to the write, which will
	// surface the real problem.
	if !created {
		if existing, err := os.ReadFile(target); err == nil && bytes.Equal(existing, data) {
			return nil
		}
	}

	// No O_TRUNC: truncating first would briefly expose a zero-length file to
	// readers. No O_NOFOLLOW: following an existing symlink chain is deliberate.
	f, openErr := os.OpenFile(target, os.O_WRONLY|os.O_CREATE, inplaceDataFileMode)
	if openErr != nil {
		return fmt.Errorf("opening file for writing: %w", openErr)
	}

	if err := writeContentsInPlace(f, data, created, fsGroup); err != nil {
		// Close is best effort here; the write error is the interesting one.
		f.Close()
		return err
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("closing file: %w", err)
	}

	return nil
}

// writeContentsInPlace performs the write on an already open file. The caller
// owns closing f.
func writeContentsInPlace(f *os.File, data []byte, created bool, fsGroup *int64) error {
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("writing contents: %w", err)
	}

	// Drop anything left over from a longer previous version of the file. This
	// happens after the write so readers never observe a short file.
	if err := f.Truncate(int64(len(data))); err != nil {
		return fmt.Errorf("truncating to written length: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("syncing contents: %w", err)
	}

	if !created {
		return nil
	}

	if err := f.Chmod(inplaceDataFileMode); err != nil {
		return fmt.Errorf("setting file mode: %w", err)
	}

	if fsGroup != nil {
		// -1 for the uid means "do not change the owner".
		if err := f.Chown(-1, int(*fsGroup)); err != nil {
			return fmt.Errorf("setting file gid to %d: %w", *fsGroup, err)
		}
	}

	return nil
}

// ensureDataDirGroup chowns the data directory to fsGroup, but only if it is
// not already owned by that group. csi-lib chowns unconditionally on every
// write, which is what produced a misleading IN_ATTRIB event while the stale
// certificate incident was being diagnosed.
func ensureDataDirGroup(dataPath string, fsGroup *int64) error {
	if fsGroup == nil {
		return nil
	}

	info, err := os.Stat(dataPath)
	if err != nil {
		return fmt.Errorf("stat data directory %q: %w", dataPath, err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int64(stat.Gid) == *fsGroup {
		return nil
	}

	if err := os.Chown(dataPath, -1, int(*fsGroup)); err != nil {
		return fmt.Errorf("failed to chown data dir to gid %v: %w", *fsGroup, err)
	}

	return nil
}

// fsGroupForMetadata returns the gid that file and data directory ownership
// should be set to, or nil if ownership should be left alone. It mirrors the
// resolution csi-lib's Filesystem performs, which is unexported there.
func (s *inplaceWriteStorage) fsGroupForMetadata(meta metadata.Metadata) (*int64, error) {
	// The volume attribute takes precedence over the VolumeMountGroup set via
	// securityContext.fsGroup, so ownership can be controlled per volume.
	fsGroupStr := ""
	if len(s.fsGroupVolumeAttributeKey) > 0 {
		fsGroupStr = meta.VolumeContext[s.fsGroupVolumeAttributeKey]
	}
	if fsGroupStr == "" {
		fsGroupStr = meta.VolumeMountGroup
	}
	if fsGroupStr == "" {
		return nil, nil
	}

	fsGroup, err := strconv.ParseInt(fsGroupStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q, value must be a valid integer: %w",
			s.fsGroupVolumeAttributeKey, err)
	}

	// 4294967295 is the largest gid on most modern operating systems. A smaller
	// real maximum will simply fail later during the chown.
	if fsGroup <= 0 || fsGroup > 4294967295 {
		return nil, fmt.Errorf("%q: gid value must be greater than 0 and less than 4294967295: %d",
			s.fsGroupVolumeAttributeKey, fsGroup)
	}

	return &fsGroup, nil
}
