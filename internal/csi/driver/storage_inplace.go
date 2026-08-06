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
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
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

	// WriteModeAtomicDir is the upstream csi-lib behaviour and the default:
	// every write creates a new timestamped directory, re-points the `..data`
	// symlink and deletes the previous directory.
	WriteModeAtomicDir = "atomic-dir"
)

const (
	// inplaceDataDirMode matches the data directory mode used by csi-lib: read
	// and execute only for the fs user and group.
	inplaceDataDirMode os.FileMode = 0550

	// inplaceDataFileMode matches the file mode used by csi-lib for projected
	// certificate data: read only for the owner and group.
	inplaceDataFileMode os.FileMode = 0440

	// atomicDataDirName is the name of the symlink the csi-lib atomic writer
	// points at the current timestamped directory. Kept in sync with
	// third_party/util.dataDirName, which is unexported there.
	atomicDataDirName = "..data"

	// atomicReservedPrefix is the prefix the atomic writer reserves for its own
	// bookkeeping entries (`..data` and the timestamped directories). Payload
	// names may not start with it, so any entry that does belongs to the writer.
	atomicReservedPrefix = ".."
)

const (
	// inplaceMaxFileNameLength and inplaceMaxPathLength mirror
	// maxFileNameLength and maxPathLength in csi-lib's vendored copy of the
	// Kubernetes atomic writer, which are unexported there.
	inplaceMaxFileNameLength = 255
	inplaceMaxPathLength     = 4096
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

var (
	_ storage.Interface = &inplaceWriteStorage{}

	// camanager detects the CA-only write path through this interface.
	_ singleFileWriter = &inplaceWriteStorage{}
)

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
// As upstream, the payload is the complete desired contents of the volume: any
// other file in the root of the data directory is removed. Beyond that nothing
// in this path deletes, renames or symlinks: the inode a mounted pod has open
// (and has an inotify watch on) must survive every write. When the volume was
// previously written by the csi-lib atomic writer the data directory still holds
// the `..data` symlink layout; opening `<data>/tls.crt` follows that chain and
// rewrites the file inside the timestamped directory, which is exactly what we
// want - the layout is left alone and live pods keep working.
func (s *inplaceWriteStorage) WriteFiles(meta metadata.Metadata, files map[string][]byte) error {
	if err := validatePayloadNames(files); err != nil {
		return err
	}

	dataPath := s.inner.PathForVolume(meta.VolumeID)

	// Only the data directory is created here, where csi-lib's
	// ensureVolumeDirectory also creates the volume directory holding
	// metadata.json. That is safe: RegisterMetadata creates the volume directory
	// when the volume is first published, and no write can reach this method for
	// a volume the driver has no metadata for.
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

	// A symlink layout whose target directory is gone can never be repaired by
	// writing through it: opening any file in it fails with ENOENT. Both shapes
	// brokenAtomicLayout recognises imply the file the symlink resolved to has
	// been deleted, so every watch that went through it is already dead, and
	// rebuilding the layout with the inner atomic writer cannot break a live
	// consumer. It is also the only way to make the volume writable again.
	broken, err := brokenAtomicLayout(dataPath, files)
	if err != nil {
		return err
	}
	if broken {
		if err := clearInplaceArtifacts(dataPath); err != nil {
			return err
		}
		return s.inner.WriteFiles(meta, files)
	}

	if err := removeUnlistedFiles(dataPath, files); err != nil {
		return err
	}

	for _, name := range orderedWriteNames(files, s.certFileName) {
		if err := writeFileInPlace(filepath.Join(dataPath, name), files[name], fsGroup); err != nil {
			return fmt.Errorf("writing file %q: %w", name, err)
		}
	}

	return nil
}

// WriteFile updates a single file in the volume's data directory in place,
// leaving every other file alone.
//
// camanager publishes trust bundle updates through this method. The alternative
// - reading the current certificate and key off the volume and writing them
// back alongside the new CA bundle, which the atomic writer's desired-state
// payload forces it to do - silently rolls back a renewal that lands between
// that read and the write: the old keypair is written over the new one while the
// renewal's metadata records success, and nothing retries until the next
// renewal. Touching only the CA file removes the race; the worst a concurrent
// renewal can do is write identical bytes to it.
func (s *inplaceWriteStorage) WriteFile(meta metadata.Metadata, name string, data []byte) error {
	if err := validatePayloadName(name); err != nil {
		return err
	}

	dataPath := s.inner.PathForVolume(meta.VolumeID)

	// See WriteFiles for why only the data directory is ensured here.
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

	// Unlike WriteFiles this must not fall back to the inner atomic writer: that
	// writer treats its payload as the complete desired state, so handing it a
	// single-file payload would delete every other file in the volume. Failing
	// is the safe answer - the pod's watches on a broken layout are already
	// dead, and the next full renewal or re-publish rebuilds the volume.
	broken, err := brokenAtomicLayout(dataPath, map[string][]byte{name: data})
	if err != nil {
		return err
	}
	if broken {
		return fmt.Errorf("cannot write %q in place: the `..data` symlink layout of volume %q is broken; "+
			"the next full write will rebuild it", name, meta.VolumeID)
	}

	if err := writeFileInPlace(filepath.Join(dataPath, name), data, fsGroup); err != nil {
		return fmt.Errorf("writing file %q: %w", name, err)
	}

	return nil
}

// atomicDirStorage is a thin decorator over the csi-lib file system storage that
// clears the in-place writer's leftovers before every atomic write.
//
// It is what makes `--volume-write-mode=atomic-dir` an actually usable rollback
// once the in-place writer has run on a node. The atomic writer cannot put a
// user-visible symlink over an existing regular file and does not notice that it
// failed to (see clearInplaceArtifacts); without this wrapper the rollback keeps
// reporting success while silently delivering no renewals at all, which is worse
// than the broken inotify watch the in-place mode exists to fix.
//
// Clearing those files does unlink an inode a pod may be watching, and leaves
// the path missing until the atomic writer publishes its symlink, so a pod that
// opens the file in between sees ENOENT. Both are inherent to rolling back to a
// writer that replaces every file on every write.
type atomicDirStorage struct {
	inner innerStore
}

var _ storage.Interface = &atomicDirStorage{}

func newAtomicDirStorage(inner innerStore) *atomicDirStorage {
	return &atomicDirStorage{inner: inner}
}

func (s *atomicDirStorage) PathForVolume(volumeID string) string {
	return s.inner.PathForVolume(volumeID)
}

func (s *atomicDirStorage) RemoveVolume(volumeID string) error {
	return s.inner.RemoveVolume(volumeID)
}

func (s *atomicDirStorage) ReadMetadata(volumeID string) (metadata.Metadata, error) {
	return s.inner.ReadMetadata(volumeID)
}

func (s *atomicDirStorage) ListVolumes() ([]string, error) {
	return s.inner.ListVolumes()
}

func (s *atomicDirStorage) WriteMetadata(volumeID string, meta metadata.Metadata) error {
	return s.inner.WriteMetadata(volumeID, meta)
}

func (s *atomicDirStorage) RegisterMetadata(meta metadata.Metadata) (bool, error) {
	return s.inner.RegisterMetadata(meta)
}

func (s *atomicDirStorage) ReadFile(volumeID, name string) ([]byte, error) {
	return s.inner.ReadFile(volumeID, name)
}

func (s *atomicDirStorage) WriteFiles(meta metadata.Metadata, files map[string][]byte) error {
	// Validate before clearing anything: the inner writer applies the same rules
	// and would reject the payload afterwards, leaving the volume emptied for a
	// write that was never going to happen.
	if err := validatePayloadNames(files); err != nil {
		return err
	}

	if err := clearInplaceArtifacts(s.inner.PathForVolume(meta.VolumeID)); err != nil {
		return err
	}

	return s.inner.WriteFiles(meta, files)
}

// clearInplaceArtifacts removes what the in-place writer left in the root of the
// volume's data directory, so that a subsequent write by the csi-lib atomic
// writer is actually visible to the mounted pod.
//
// util.AtomicWriter.createUserVisibleFiles decides whether it has to create the
// user-visible symlink for a payload name by calling os.Readlink on it and
// testing the error with os.IsNotExist. On anything that is not a symlink
// Readlink fails with EINVAL, not ENOENT, so the branch is skipped: no symlink is
// created, Write still returns nil, and everything the atomic writer wrote sits
// in a timestamped directory that nothing points at. The pod goes on reading the
// stale path indefinitely and no error is reported anywhere.
//
// Both regular files and real directories have to go, and only symlinks may
// stay. Every root-level entry the atomic writer owns is either a symlink (the
// `..data` link, and one per first path segment of a payload name - see
// createUserVisibleFiles, which symlinks the segment rather than creating a
// directory) or `..`-prefixed bookkeeping (`..data` and the timestamped
// directories). So a non-`..` regular file or real directory in the root can only
// be an in-place artifact: the file from a flat payload name, or the parent
// directory writeFileInPlace creates for a nested one. Removing it is precisely
// what lets createUserVisibleFiles create the symlink.
func clearInplaceArtifacts(dataPath string) error {
	entries, err := os.ReadDir(dataPath)
	if errors.Is(err, os.ErrNotExist) {
		// Nothing has been written yet; the atomic writer builds the layout
		// from scratch.
		return nil
	}
	if err != nil {
		return fmt.Errorf("listing data directory %q: %w", dataPath, err)
	}

	for _, entry := range entries {
		// Symlinks are the atomic writer's own user-visible entries: leave them
		// be, they are what it expects to find and reuse.
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		// `..`-prefixed entries are its bookkeeping, and a payload name can never
		// collide with them (see validatePayloadName).
		if strings.HasPrefix(entry.Name(), atomicReservedPrefix) {
			continue
		}

		target := filepath.Join(dataPath, entry.Name())
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("removing in-place written path %q: %w", target, err)
		}
	}

	return nil
}

// removeUnlistedFiles deletes the root-level entries of the data directory that
// the payload does not contain, so that a write means the same thing it does
// upstream: the payload is the complete desired file set, not a partial update.
// Without this a file that stops being generated - a keystore after keystore
// support is switched off, or a file that was renamed - would be served to the
// pod forever.
//
// Only root-level entries are pruned, as in upstream removeUserVisiblePaths, and
// `..`-prefixed names are preserved. Upstream then loses the superseded contents
// by rebuilding the timestamped directory from scratch, which the in-place writer
// deliberately never does - so in a legacy `..data` layout this removes the
// user-visible symlink *and* the file it pointed at inside the timestamped
// directory, leaving `..data`, the directory itself and every other file in it
// untouched. Deleting the file behind the link matters for more than tidiness:
// upstream's pathsToRemove walks the timestamped directory, and a file left there
// with no user-visible link makes the first atomic-dir write after a rollback fail
// in removeUserVisiblePaths, trying to os.Remove a path that is already gone.
//
// One consequence of pruning only the root is that an obsolete file inside a
// payload subdirectory survives. No payload this driver produces is nested, so
// nothing relies on that today.
//
// Callers must run this before the writes, so the certificate - written last -
// still fires the event that tells the consumer the on-disk set is final.
func removeUnlistedFiles(dataPath string, files map[string][]byte) error {
	entries, err := os.ReadDir(dataPath)
	if err != nil {
		return fmt.Errorf("listing data directory %q: %w", dataPath, err)
	}

	wanted := make(map[string]struct{}, len(files))
	for name := range files {
		wanted[payloadRootName(name)] = struct{}{}
	}

	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, atomicReservedPrefix) {
			continue
		}
		if _, ok := wanted[name]; ok {
			continue
		}

		// A symlink here is a user-visible link into `..data`; drop what it points
		// at as well, so nothing is left in the timestamped directory without a
		// link to it. RemoveAll rather than Remove: it treats an already absent
		// path as success, and handles the directory a nested payload name would
		// have put there. The trailing element is never followed, but the
		// intermediate `..data` link is, so this reaches outside the volume if
		// `..data` itself has been maliciously re-pointed - the same trust
		// boundary as the O_NOFOLLOW note on writeFileInPlace: only a node-level
		// writer could plant such a link, since pods mount the volume read-only.
		if entry.Type()&os.ModeSymlink != 0 {
			behindLink := filepath.Join(dataPath, atomicDataDirName, name)
			if err := os.RemoveAll(behindLink); err != nil {
				return fmt.Errorf("removing obsolete path %q: %w", behindLink, err)
			}
		}

		target := filepath.Join(dataPath, name)
		if err := os.RemoveAll(target); err != nil {
			return fmt.Errorf("removing obsolete path %q: %w", target, err)
		}
	}

	return nil
}

// payloadRootName returns the first path element of a cleaned payload name,
// which is the root-level entry that name occupies in the data directory. It is
// the same value upstream createUserVisibleFiles symlinks, and the cleaning
// mirrors upstream validatePayload keying its payload by filepath.Clean.
func payloadRootName(name string) string {
	clean := filepath.Clean(name)
	if i := strings.Index(clean, string(os.PathSeparator)); i != -1 {
		return clean[:i]
	}

	return clean
}

// validatePayloadNames rejects a payload before anything is written, applying
// the same rules as validatePath in csi-lib's vendored copy of the Kubernetes
// atomic writer. The in-place writer bypasses that writer, so it has to do the
// validation itself: without it a name such as `../../metadata.json` would
// escape the volume's data directory.
func validatePayloadNames(files map[string][]byte) error {
	for name := range files {
		if err := validatePayloadName(name); err != nil {
			return err
		}
	}

	return nil
}

// validatePayloadName mirrors validatePath in csi-lib's vendored atomic writer,
// plus one stricter rule (no `.`, see below).
// A name may not be empty or absolute, may not contain `..` as a path element,
// may not have a first element that starts with `..` and is longer than two
// characters (the writer reserves those for its own bookkeeping), may not exceed
// inplaceMaxPathLength in total and may not contain an element longer than
// inplaceMaxFileNameLength.
func validatePayloadName(name string) error {
	if name == "" {
		return fmt.Errorf("invalid path: must not be empty: %q", name)
	}
	if path.IsAbs(name) {
		return fmt.Errorf("invalid path: must be relative path: %s", name)
	}
	// Stricter than upstream, which accepts `.`: here it would make
	// removeUnlistedFiles prune the whole data directory and the write then fail
	// on the directory itself, leaving the volume empty.
	if filepath.Clean(name) == "." {
		return fmt.Errorf("invalid path: must name a file, not the data directory itself: %q", name)
	}
	if len(name) > inplaceMaxPathLength {
		return fmt.Errorf("invalid path: must be less than or equal to %d characters", inplaceMaxPathLength)
	}

	items := strings.Split(name, string(os.PathSeparator))
	for _, item := range items {
		if item == ".." {
			return fmt.Errorf("invalid path: must not contain '..': %s", name)
		}
		if len(item) > inplaceMaxFileNameLength {
			return fmt.Errorf("invalid path: filenames must be less than or equal to %d characters",
				inplaceMaxFileNameLength)
		}
	}
	if strings.HasPrefix(items[0], atomicReservedPrefix) && len(items[0]) > 2 {
		return fmt.Errorf("invalid path: must not start with '..': %s", name)
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

// brokenAtomicLayout reports whether the volume still holds an atomic-writer
// layout that has been torn half down, which no amount of writing through it can
// repair. Only then may a caller hand the volume back to the atomic writer,
// because doing so deletes the timestamped directory and with it every inode a
// pod is watching.
//
// Two shapes qualify:
//
//   - `..data` is a symlink that no longer resolves. Every user-visible symlink
//     points through it, so no file in the volume can be opened.
//   - `..data` is absent entirely and a payload name is a symlink that does not
//     resolve. It can only point into the data directory that is gone, and
//     opening it with O_CREATE would fail with ENOENT.
//
// A dangling per-file symlink while `..data` does resolve is explicitly healthy:
// O_CREATE follows the chain and creates the file inside the timestamped
// directory, repairing it in place. Treating that as broken - which an earlier
// version of this check did - rebuilt the whole layout and destroyed the live
// watches on every still-healthy sibling file, which is the failure this write
// mode exists to prevent.
func brokenAtomicLayout(dataPath string, files map[string][]byte) (bool, error) {
	dataDir := filepath.Join(dataPath, atomicDataDirName)

	info, err := os.Lstat(dataDir)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink == 0 {
			// Not the writer's symlink; there is no chain to be broken.
			return false, nil
		}

		if _, err := os.Stat(dataDir); errors.Is(err, os.ErrNotExist) {
			return true, nil
		} else if err != nil {
			return false, fmt.Errorf("resolving %q: %w", dataDir, err)
		}

		return false, nil

	case !errors.Is(err, os.ErrNotExist):
		return false, fmt.Errorf("checking %q: %w", dataDir, err)
	}

	// No `..data` at all, so a user-visible symlink cannot be repaired by
	// writing through it.
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
	// A nested payload name needs its parent directory created first, as
	// upstream writePayloadToDir does and with the same os.ModePerm, so the
	// mounting pod's user and group can traverse into it. For a flat name the
	// parent is the data directory, which the caller has already created and
	// which MkdirAll then leaves untouched.
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, os.ModePerm); err != nil {
		return fmt.Errorf("creating parent directory %q: %w", parent, err)
	}

	// Stat, not Lstat, so we can tell a file we are creating from one that
	// already exists: a dangling symlink counts as a create, because the file
	// behind it is about to come into existence. Only a freshly created file
	// needs its mode and group ownership set; re-applying them on every write is
	// pure metadata churn that wakes every watcher with an IN_ATTRIB event for
	// no reason.
	_, err := os.Stat(target)
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
			// Content is already correct, but ownership may not be: the volume
			// can be re-published with a different fsGroup without the
			// certificate changing.
			return ensureFileGroup(target, fsGroup)
		}
	}

	// No O_TRUNC: truncating first would briefly expose a zero-length file to
	// readers. No O_NOFOLLOW: following an existing symlink chain is deliberate,
	// and it is what keeps a legacy `..data` layout working.
	//
	// That does mean a symlink already sitting in the data directory redirects
	// this write to wherever it points, including outside the volume. Upstream is
	// structurally immune because it only ever writes into a directory it just
	// created. Here the argument is narrower: a pod cannot plant one, because
	// csi-lib refuses a volume that is not readOnly and bind mounts the data
	// directory `ro` into the pod (driver/nodeserver.go), so only something with
	// write access to the node's own tmpfs could - and that already has the
	// driver's privileges. Any change that loosens the read-only mount invalidates
	// this reasoning and would need O_NOFOLLOW plus explicit chain validation.
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

	if !created {
		// writeContentsInPlace deliberately leaves an existing file's metadata
		// alone, so repair its group here if the volume's fsGroup has changed
		// since the file was created.
		return ensureFileGroup(target, fsGroup)
	}

	return nil
}

// writeContentsInPlace performs the write on an already open file. The caller
// owns closing f.
func writeContentsInPlace(f *os.File, data []byte, created bool, fsGroup *int64) error {
	if _, err := f.WriteAt(data, 0); err != nil {
		return fmt.Errorf("writing contents: %w", err)
	}

	// Drop anything left over from a longer previous version of the file.
	//
	// This is not atomic against a concurrent reader, and neither is the WriteAt
	// above: between the two syscalls a reader can observe the new content
	// followed by the tail of the old (the window is widest when the new content
	// is shorter), and a multi-page write is not atomic on tmpfs either. What
	// does hold is the event ordering: both syscalls emit IN_MODIFY, so the last
	// event a watcher receives is always emitted after the final content is
	// complete. A consumer that re-reads on every event therefore converges; one
	// that reads inside the window has to tolerate a parse failure until the
	// next event arrives.
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

// ensureFileGroup chowns target to fsGroup, but only if it is not already owned
// by that group: an unconditional chown emits IN_ATTRIB and wakes every watcher
// for a change that did not happen.
func ensureFileGroup(target string, fsGroup *int64) error {
	if fsGroup == nil {
		return nil
	}

	// Stat, not Lstat: ownership belongs on the file the symlink chain resolves
	// to, which is the file the pod actually reads.
	info, err := os.Stat(target)
	if err != nil {
		return fmt.Errorf("stat %q: %w", target, err)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && int64(stat.Gid) == *fsGroup {
		return nil
	}

	if err := os.Chown(target, -1, int(*fsGroup)); err != nil {
		return fmt.Errorf("failed to chown %q to gid %v: %w", target, *fsGroup, err)
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
	// securityContext.fsGroup, so ownership can be controlled per volume. The
	// source is tracked so an error names the field the operator actually set.
	fsGroupStr, source := "", ""
	if len(s.fsGroupVolumeAttributeKey) > 0 {
		fsGroupStr = meta.VolumeContext[s.fsGroupVolumeAttributeKey]
		source = fmt.Sprintf("volume attribute %q", s.fsGroupVolumeAttributeKey)
	}
	if fsGroupStr == "" {
		fsGroupStr = meta.VolumeMountGroup
		source = "volume mount group"
	}
	if fsGroupStr == "" {
		return nil, nil
	}

	fsGroup, err := strconv.ParseInt(fsGroupStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s value %q, value must be a valid integer: %w",
			source, fsGroupStr, err)
	}

	// 4294967295 is the largest gid on most modern operating systems. A smaller
	// real maximum will simply fail later during the chown.
	if fsGroup <= 0 || fsGroup > 4294967295 {
		return nil, fmt.Errorf("%s: gid value must be greater than 0 and less than 4294967295: %d",
			source, fsGroup)
	}

	return &fsGroup, nil
}
