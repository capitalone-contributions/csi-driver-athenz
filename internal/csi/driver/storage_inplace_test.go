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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/cert-manager/csi-lib/third_party/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeWithRealAtomicWriter runs the actual csi-lib atomic writer over dataPath.
// The fake inner store cannot cover the rollback path: the whole failure mode is
// that the real writer reports success while silently dropping the write, so the
// only way to prove a rollback works is to run it.
func writeWithRealAtomicWriter(t *testing.T, dataPath string, files map[string]string) error {
	t.Helper()

	writer, err := util.NewAtomicWriter(dataPath, "test")
	require.NoError(t, err)

	payload := map[string]util.FileProjection{}
	for name, data := range files {
		payload[name] = util.FileProjection{Data: []byte(data), Mode: int32(inplaceDataFileMode)}
	}

	return writer.Write(payload, nil)
}

// fakeInnerStore stands in for *storage.Filesystem. The real one cannot be used
// in a unit test: storage.NewFilesystem mounts a tmpfs, and the fields needed to
// build one by hand are unexported.
type fakeInnerStore struct {
	dataPath string

	// writeFilesCalls counts delegations to the inner (atomic) writer. The
	// in-place writer is expected to delegate only when the existing symlink
	// layout is broken beyond in-place repair.
	writeFilesCalls int

	// sawNonSymlinkEntries records the root-level entries that were still in the
	// data directory when the delegation happened and were not symlinks. The real
	// atomic writer probes each payload name with os.Readlink and only publishes
	// the user-visible symlink when that fails with ENOENT; a regular file or a
	// real directory fails with EINVAL instead, so the write is silently dropped
	// and anything recorded here would never have reached the pod.
	sawNonSymlinkEntries []string
}

func (f *fakeInnerStore) PathForVolume(volumeID string) string { return f.dataPath }
func (f *fakeInnerStore) RemoveVolume(string) error            { return nil }
func (f *fakeInnerStore) ListVolumes() ([]string, error)       { return nil, nil }

func (f *fakeInnerStore) ReadMetadata(string) (metadata.Metadata, error) {
	return metadata.Metadata{}, nil
}
func (f *fakeInnerStore) WriteMetadata(string, metadata.Metadata) error    { return nil }
func (f *fakeInnerStore) RegisterMetadata(metadata.Metadata) (bool, error) { return false, nil }
func (f *fakeInnerStore) ReadFile(string, string) ([]byte, error)          { return nil, nil }

// WriteFiles records the delegation and the state of the data directory at that
// moment. On a healthy volume the in-place writer does all writing itself; it
// only hands over to the inner atomic writer to rebuild a volume whose symlink
// layout is broken, or when the driver is running in atomic-dir mode.
func (f *fakeInnerStore) WriteFiles(metadata.Metadata, map[string][]byte) error {
	f.writeFilesCalls++

	f.sawNonSymlinkEntries = []string{}
	entries, err := os.ReadDir(f.dataPath)
	if err != nil {
		return fmt.Errorf("fake inner store: listing %q: %w", f.dataPath, err)
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if strings.HasPrefix(entry.Name(), atomicReservedPrefix) {
			continue
		}
		f.sawNonSymlinkEntries = append(f.sawNonSymlinkEntries, entry.Name())
	}

	return nil
}

var _ innerStore = &fakeInnerStore{}

// newTestInplaceStorage returns an in-place writer over a temp data directory,
// plus that directory. The directory is created up-front with a mode that
// permits writes: the production mode (0550) relies on the driver running as
// root.
func newTestInplaceStorage(t *testing.T, certFileName string) (*inplaceWriteStorage, string) {
	t.Helper()

	dataPath := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.MkdirAll(dataPath, 0o755))

	return &inplaceWriteStorage{
		inner:                     &fakeInnerStore{dataPath: dataPath},
		certFileName:              certFileName,
		fsGroupVolumeAttributeKey: "csi.cert-manager.athenz.io/fs-group",
	}, dataPath
}

// makeWritableForRewrite relaxes the 0440 mode of already-written files so a
// second WriteFiles can reopen them as a non-root test user. The driver itself
// runs as root, where reopening a 0440 file for writing is allowed.
func makeWritableForRewrite(t *testing.T, dataPath string, names ...string) {
	t.Helper()

	if os.Geteuid() == 0 {
		return
	}
	for _, name := range names {
		require.NoError(t, os.Chmod(filepath.Join(dataPath, name), 0o640))
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "expected a *syscall.Stat_t for %q", path)

	return uint64(stat.Ino)
}

func Test_inplaceWriteStorage_WriteFiles_preservesInodes(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")
	meta := metadata.Metadata{VolumeID: "vol-id"}

	names := []string{"tls.crt", "tls.key", "ca.crt"}

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("cert-1"),
		"tls.key": []byte("key-1"),
		"ca.crt":  []byte("ca-1"),
	}))

	before := map[string]uint64{}
	for _, name := range names {
		before[name] = inodeOf(t, filepath.Join(dataPath, name))
	}

	makeWritableForRewrite(t, dataPath, names...)

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("cert-2"),
		"tls.key": []byte("key-2"),
		"ca.crt":  []byte("ca-2"),
	}))

	for _, name := range names {
		assert.Equal(t, before[name], inodeOf(t, filepath.Join(dataPath, name)),
			"inode of %q changed across writes: the file was replaced rather than "+
				"rewritten in place (a temp file + rename, or the csi-lib atomic "+
				"writer, does exactly this). Any inotify watch a pod holds on this "+
				"file is destroyed, and the consumer keeps serving a stale cert.", name)
	}

	for name, want := range map[string]string{
		"tls.crt": "cert-2",
		"tls.key": "key-2",
		"ca.crt":  "ca-2",
	} {
		got, err := os.ReadFile(filepath.Join(dataPath, name))
		require.NoError(t, err)
		assert.Equal(t, want, string(got), "reader should observe the second write of %q", name)
	}
}

func Test_inplaceWriteStorage_WriteFiles_freshVolumeLayout(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt": []byte("cert"),
		"tls.key": []byte("key"),
	}))

	entries, err := os.ReadDir(dataPath)
	require.NoError(t, err)

	var got []string
	for _, entry := range entries {
		assert.False(t, strings.HasPrefix(entry.Name(), ".."),
			"unexpected atomic-writer entry %q in the data directory", entry.Name())
		got = append(got, entry.Name())
	}
	assert.ElementsMatch(t, []string{"tls.crt", "tls.key"}, got)

	for _, name := range []string{"tls.crt", "tls.key"} {
		info, err := os.Lstat(filepath.Join(dataPath, name))
		require.NoError(t, err)
		assert.True(t, info.Mode().IsRegular(), "%q should be a regular file, not a symlink", name)
		assert.Equal(t, os.FileMode(0o440), info.Mode().Perm(), "mode of %q", name)
	}
}

// A volume previously written by the csi-lib atomic writer still has the
// `..data` symlink layout. Writing must follow that chain: recreating the layout
// would unlink the inode the running pod is watching.
func Test_inplaceWriteStorage_WriteFiles_writesThroughLegacyDataSymlink(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	tsDir := filepath.Join(dataPath, "..2026_01_01_00_00_00.1")
	require.NoError(t, os.MkdirAll(tsDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(tsDir, "tls.crt"), []byte("cert-old"), 0o640))
	require.NoError(t, os.Symlink("..2026_01_01_00_00_00.1", filepath.Join(dataPath, "..data")))
	require.NoError(t, os.Symlink(filepath.Join("..data", "tls.crt"), filepath.Join(dataPath, "tls.crt")))

	before := inodeOf(t, filepath.Join(tsDir, "tls.crt"))

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt": []byte("cert-new"),
	}))

	info, err := os.Lstat(filepath.Join(dataPath, "tls.crt"))
	require.NoError(t, err)
	assert.NotZero(t, info.Mode()&os.ModeSymlink,
		"the existing `..data` symlink layout must be left in place")

	assert.DirExists(t, tsDir, "the timestamped directory must not be deleted")
	assert.Equal(t, before, inodeOf(t, filepath.Join(tsDir, "tls.crt")),
		"the underlying file was replaced instead of rewritten, destroying the pod's watch")

	got, err := os.ReadFile(filepath.Join(dataPath, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, "cert-new", string(got))
}

func Test_inplaceWriteStorage_WriteFiles_truncatesShorterContent(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")
	meta := metadata.Metadata{VolumeID: "vol-id"}

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("a-much-longer-certificate-payload"),
	}))
	makeWritableForRewrite(t, dataPath, "tls.crt")

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("short"),
	}))

	got, err := os.ReadFile(filepath.Join(dataPath, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, "short", string(got), "trailing bytes of the previous write were not truncated")
}

// Identical content must not be rewritten: every write wakes the pod's watcher
// (istio-agent reloads the certificate) for a no-op update, and camanager
// rewrites all files on every trust-bundle change even when nothing differs.
func Test_inplaceWriteStorage_WriteFiles_skipsIdenticalContent(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")
	meta := metadata.Metadata{VolumeID: "vol-id"}

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{"tls.crt": []byte("same")}))

	target := filepath.Join(dataPath, "tls.crt")

	// Backdate the file to a sentinel rather than sleeping between the writes:
	// the modification time only has to differ from "now", and a sleep short
	// enough to keep the test fast is below the timestamp resolution of several
	// common file systems, which made this assertion pass regardless.
	sentinel := time.Now().Add(-time.Hour).Truncate(time.Second)
	require.NoError(t, os.Chtimes(target, sentinel, sentinel))

	// Deliberately no makeWritableForRewrite: an identical write must return
	// before even opening the file, so the 0440 mode never gets in the way.
	require.NoError(t, s.WriteFiles(meta, map[string][]byte{"tls.crt": []byte("same")}))

	after, err := os.Stat(target)
	require.NoError(t, err)
	assert.True(t, after.ModTime().Equal(sentinel),
		"identical content was rewritten (mod time moved from %s to %s); the pod's watcher "+
			"would be woken for a no-op reload", sentinel, after.ModTime())
}

// A half-torn-down atomic-writer layout (a `..data` chain whose timestamped
// directory is gone) cannot be repaired by writing through it. The writer must
// delegate to the inner atomic writer to rebuild the volume; watches on the old
// inodes are already dead at that point, so this cannot break a live consumer.
func Test_inplaceWriteStorage_WriteFiles_rebuildsBrokenSymlinkLayout(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	// The `..data` chain exists, but the timestamped directory it points at
	// does not.
	require.NoError(t, os.Symlink("..2026_01_01_00_00_00.1", filepath.Join(dataPath, "..data")))
	require.NoError(t, os.Symlink(filepath.Join("..data", "tls.crt"), filepath.Join(dataPath, "tls.crt")))

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt": []byte("cert-new"),
		"tls.key": []byte("key-new"),
	}))

	fake := s.inner.(*fakeInnerStore)
	assert.Equal(t, 1, fake.writeFilesCalls,
		"a broken symlink layout must be rebuilt by delegating to the inner atomic writer")

	// Nothing must have been written in place around the broken chain.
	_, err := os.Stat(filepath.Join(dataPath, "tls.key"))
	assert.True(t, os.IsNotExist(err), "the in-place path must not run once the layout is known to be broken")
}

// writeLegacyAtomicLayout builds the `..data` symlink layout the csi-lib atomic
// writer leaves behind, with the given name/content pairs living inside the
// timestamped directory. It returns the timestamped directory.
func writeLegacyAtomicLayout(t *testing.T, dataPath string, files map[string]string) string {
	t.Helper()

	const tsName = "..2026_01_01_00_00_00.1"
	tsDir := filepath.Join(dataPath, tsName)
	require.NoError(t, os.MkdirAll(tsDir, 0o755))

	for name, data := range files {
		require.NoError(t, os.WriteFile(filepath.Join(tsDir, name), []byte(data), 0o640))
		require.NoError(t, os.Symlink(
			filepath.Join(atomicDataDirName, name), filepath.Join(dataPath, name)))
	}
	require.NoError(t, os.Symlink(tsName, filepath.Join(dataPath, atomicDataDirName)))

	return tsDir
}

// Rolling back to `--volume-write-mode=atomic-dir` on a node the in-place writer
// has already run on must actually deliver renewals. The atomic writer probes
// each payload name with os.Readlink and only creates the user-visible symlink
// when that fails with ENOENT; on a regular file it fails with EINVAL, so the
// symlink is never created, Write() still returns nil, and the pod keeps reading
// the stale regular file forever. The wrapper has to clear those files first.
func Test_atomicDirStorage_WriteFiles_clearsInplaceRegularFiles(t *testing.T) {
	inplace, dataPath := newTestInplaceStorage(t, "tls.crt")
	fake := inplace.inner.(*fakeInnerStore)
	meta := metadata.Metadata{VolumeID: "vol-id"}

	require.NoError(t, inplace.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("cert"),
		"tls.key": []byte("key"),
	}))
	for _, name := range []string{"tls.crt", "tls.key"} {
		info, err := os.Lstat(filepath.Join(dataPath, name))
		require.NoError(t, err)
		require.True(t, info.Mode().IsRegular(), "%q should have been written as a regular file", name)
	}

	atomicDir := newAtomicDirStorage(fake)
	require.NoError(t, atomicDir.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("cert-2"),
		"tls.key": []byte("key-2"),
	}))

	assert.Equal(t, 1, fake.writeFilesCalls,
		"the atomic-dir wrapper must still delegate the write to the csi-lib atomic writer")
	assert.Empty(t, fake.sawNonSymlinkEntries,
		"the in-place regular files were still present when the atomic writer ran; it would "+
			"have skipped creating their user-visible symlinks and silently written to a "+
			"timestamped directory nothing points at")

	// The fake writes nothing, so the files must simply be gone.
	for _, name := range []string{"tls.crt", "tls.key"} {
		_, err := os.Lstat(filepath.Join(dataPath, name))
		assert.True(t, os.IsNotExist(err), "%q should have been cleared before delegation", name)
	}
}

// A nested payload name makes the in-place writer create a real directory at the
// data-dir root, and os.Readlink fails with EINVAL on a directory just as it does
// on a regular file. Upstream never puts a real directory there - it symlinks the
// first path segment into `..data` - so the wrapper must clear directories too or
// the rollback silently stalls on the old nested contents.
func Test_atomicDirStorage_WriteFiles_clearsInplaceDirectories(t *testing.T) {
	inplace, dataPath := newTestInplaceStorage(t, "tls.crt")
	fake := inplace.inner.(*fakeInnerStore)
	meta := metadata.Metadata{VolumeID: "vol-id"}

	require.NoError(t, inplace.WriteFiles(meta, map[string][]byte{"sub/ca.crt": []byte("ca")}))

	info, err := os.Lstat(filepath.Join(dataPath, "sub"))
	require.NoError(t, err)
	require.True(t, info.IsDir(), "the in-place writer should have created `sub` as a real directory")

	atomicDir := newAtomicDirStorage(fake)
	require.NoError(t, atomicDir.WriteFiles(meta, map[string][]byte{"sub/ca.crt": []byte("ca-2")}))

	assert.Equal(t, 1, fake.writeFilesCalls, "the write must still be delegated")
	assert.Empty(t, fake.sawNonSymlinkEntries,
		"the in-place directory was still present when the atomic writer ran; os.Readlink on it "+
			"fails with EINVAL, so no user-visible symlink is created, Write() returns nil and "+
			"the pod keeps reading the old sub/ca.crt forever")

	_, err = os.Lstat(filepath.Join(dataPath, "sub"))
	assert.True(t, os.IsNotExist(err), "`sub` should have been cleared before delegation")
}

// Clearing is destructive, so it must not happen for a payload the inner writer
// is going to reject anyway - that would empty the volume for a write that never
// had a chance of succeeding.
func Test_atomicDirStorage_WriteFiles_validatesBeforeClearing(t *testing.T) {
	inplace, dataPath := newTestInplaceStorage(t, "tls.crt")
	fake := inplace.inner.(*fakeInnerStore)
	meta := metadata.Metadata{VolumeID: "vol-id"}

	require.NoError(t, inplace.WriteFiles(meta, map[string][]byte{"tls.crt": []byte("cert")}))

	atomicDir := newAtomicDirStorage(fake)
	err := atomicDir.WriteFiles(meta, map[string][]byte{"../oops": []byte("nope")})
	require.Error(t, err, "an escaping payload name must be rejected")

	assert.Equal(t, 0, fake.writeFilesCalls, "an invalid payload must not be delegated")
	assert.FileExists(t, filepath.Join(dataPath, "tls.crt"),
		"the existing certificate was cleared for a write that could never succeed")
}

// camanager picks its write path by type-asserting the store to
// singleFileWriter. atomic-dir mode must not satisfy it: the atomic writer
// treats its payload as the complete desired contents of the volume, so a
// CA-only payload would delete the certificate and key.
func Test_writeModeSurfaces_singleFileWriter(t *testing.T) {
	var atomicDir storage.Interface = newAtomicDirStorage(&fakeInnerStore{})
	_, ok := atomicDir.(singleFileWriter)
	assert.False(t, ok,
		"atomicDirStorage must not implement singleFileWriter: camanager would send the atomic "+
			"writer a CA-only payload and it would prune the certificate and key")

	var inplace storage.Interface = &inplaceWriteStorage{}
	_, ok = inplace.(singleFileWriter)
	assert.True(t, ok,
		"inplaceWriteStorage must implement singleFileWriter, or camanager falls back to the "+
			"read-keypair-then-rewrite path that races with certificate renewal")
}

// The broken-layout fallback inside WriteFiles hands the volume to the same
// atomic writer, so it needs the same clean-up: a volume can hold both a torn
// `..data` chain and regular files written in place before the chain broke.
func Test_inplaceWriteStorage_WriteFiles_brokenLayoutFallbackClearsRegularFiles(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	// A `..data` chain whose timestamped directory is gone, next to a regular
	// file the in-place writer left behind.
	require.NoError(t, os.Symlink("..2026_01_01_00_00_00.1", filepath.Join(dataPath, atomicDataDirName)))
	require.NoError(t, os.WriteFile(filepath.Join(dataPath, "tls.key"), []byte("key"), 0o640))

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt": []byte("cert-new"),
		"tls.key": []byte("key-new"),
	}))

	fake := s.inner.(*fakeInnerStore)
	assert.Equal(t, 1, fake.writeFilesCalls, "a broken `..data` chain must be rebuilt by the atomic writer")
	assert.Empty(t, fake.sawNonSymlinkEntries,
		"the atomic writer cannot publish over a regular file, so the fallback must clear them first")

	assert.FileExists(t, filepath.Join(dataPath, atomicDataDirName),
		"only regular files may be cleared; the `..data` symlink belongs to the atomic layout")
}

// The reviewer's reproduction: one healthy symlink chain and one dangling
// sibling. `..data` still resolves, so O_CREATE through the sibling's symlink
// creates the missing file inside the timestamped directory. Delegating instead
// would rebuild the layout, delete the timestamped directory, and destroy the
// pod's live watch on the perfectly healthy certificate.
func Test_inplaceWriteStorage_WriteFiles_repairsDanglingSiblingUnderHealthyDataLink(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	tsDir := writeLegacyAtomicLayout(t, dataPath, map[string]string{"tls.crt": "cert-old"})

	// service.jks is published but its backing file was never written.
	require.NoError(t, os.Symlink(
		filepath.Join(atomicDataDirName, "service.jks"), filepath.Join(dataPath, "service.jks")))

	before := inodeOf(t, filepath.Join(tsDir, "tls.crt"))

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt":     []byte("cert-new"),
		"service.jks": []byte("jks"),
	}))

	fake := s.inner.(*fakeInnerStore)
	assert.Equal(t, 0, fake.writeFilesCalls,
		"a dangling sibling symlink under a `..data` link that still resolves is repairable in "+
			"place; delegating rebuilds the layout and destroys the watch on every healthy file")

	assert.DirExists(t, tsDir, "the timestamped directory must not be deleted")
	assert.Equal(t, before, inodeOf(t, filepath.Join(tsDir, "tls.crt")),
		"the certificate was replaced instead of rewritten, destroying the pod's watch")

	for name, want := range map[string]string{"tls.crt": "cert-new", "service.jks": "jks"} {
		got, err := os.ReadFile(filepath.Join(dataPath, name))
		require.NoError(t, err)
		assert.Equal(t, want, string(got), "reader should observe the new content of %q", name)
	}
	assert.FileExists(t, filepath.Join(tsDir, "service.jks"),
		"the missing file should have been created through the existing symlink chain")
}

// The payload is the complete desired contents of the volume, as it is upstream.
// A file that stops being generated - a keystore after keystore support is
// switched off, or a file that was renamed - must not be served forever.
func Test_inplaceWriteStorage_WriteFiles_removesFilesMissingFromPayload(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")
	meta := metadata.Metadata{VolumeID: "vol-id"}

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{
		"tls.crt":        []byte("cert-1"),
		"tls.key":        []byte("key-1"),
		"service.pkcs12": []byte("p12"),
	}))

	before := map[string]uint64{
		"tls.crt": inodeOf(t, filepath.Join(dataPath, "tls.crt")),
		"tls.key": inodeOf(t, filepath.Join(dataPath, "tls.key")),
	}
	makeWritableForRewrite(t, dataPath, "tls.crt", "tls.key")

	require.NoError(t, s.WriteFiles(meta, map[string][]byte{
		"tls.crt": []byte("cert-2"),
		"tls.key": []byte("key-2"),
	}))

	_, err := os.Lstat(filepath.Join(dataPath, "service.pkcs12"))
	assert.True(t, os.IsNotExist(err),
		"a file dropped from the payload is still on disk; the pod would keep reading a stale "+
			"keystore that no longer matches the certificate")

	for name, want := range map[string]string{"tls.crt": "cert-2", "tls.key": "key-2"} {
		got, err := os.ReadFile(filepath.Join(dataPath, name))
		require.NoError(t, err)
		assert.Equal(t, want, string(got))
		assert.Equal(t, before[name], inodeOf(t, filepath.Join(dataPath, name)),
			"pruning must not disturb the inode of %q", name)
	}
}

// In a legacy layout the entry to prune is the user-visible symlink, and the file
// it pointed at inside the timestamped directory has to go with it. `..data`, the
// timestamped directory itself and every file still in the payload must be left
// alone.
func Test_inplaceWriteStorage_WriteFiles_removesObsoleteUserVisibleSymlink(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	tsDir := writeLegacyAtomicLayout(t, dataPath, map[string]string{
		"tls.crt":        "cert-old",
		"service.pkcs12": "p12",
	})

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt": []byte("cert-new"),
	}))

	_, err := os.Lstat(filepath.Join(dataPath, "service.pkcs12"))
	assert.True(t, os.IsNotExist(err), "the user-visible symlink of a dropped file must be removed")

	// Leaving the superseded file in the timestamped directory desyncs a later
	// atomic-dir rollback: upstream pathsToRemove walks that directory, finds an
	// entry with no user-visible link, and removeUserVisiblePaths then fails
	// trying to os.Remove a path that is already gone.
	_, err = os.Lstat(filepath.Join(tsDir, "service.pkcs12"))
	assert.True(t, os.IsNotExist(err),
		"the file behind the pruned symlink is still in the timestamped directory; the first "+
			"atomic-dir write after a rollback would fail and leave the old directory behind")

	assert.DirExists(t, tsDir, "the timestamped directory is the atomic writer's; leave it alone")
	assert.FileExists(t, filepath.Join(dataPath, atomicDataDirName), "`..data` must survive pruning")
	assert.FileExists(t, filepath.Join(tsDir, "tls.crt"),
		"only the pruned name may be removed from the timestamped directory")

	got, err := os.ReadFile(filepath.Join(dataPath, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, "cert-new", string(got))
}

// End-to-end rollback against the real atomic writer: after in-place has run,
// clearing its artifacts must leave a volume the atomic writer can publish into.
// The flat case covers the leftover regular file, the nested case the leftover
// real directory - os.Readlink fails with EINVAL on both, and the writer treats
// that as "the symlink already exists" and returns success having published
// nothing.
func Test_clearInplaceArtifacts_realAtomicWriterPublishesAfterwards(t *testing.T) {
	for _, name := range []string{"tls.crt", "sub/ca.crt"} {
		t.Run(name, func(t *testing.T) {
			s, dataPath := newTestInplaceStorage(t, "tls.crt")

			require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"},
				map[string][]byte{name: []byte("in-place-bytes")}))

			require.NoError(t, clearInplaceArtifacts(dataPath))
			require.NoError(t, writeWithRealAtomicWriter(t, dataPath, map[string]string{name: "rolled-back"}))

			got, err := os.ReadFile(filepath.Join(dataPath, name))
			require.NoError(t, err)
			assert.Equal(t, "rolled-back", string(got),
				"the atomic writer reported success but %q still serves the in-place bytes: its "+
					"os.Readlink probe failed with EINVAL on the leftover, so the user-visible "+
					"symlink was never created and the write went to a directory nothing points at",
				name)
		})
	}
}

// Pruning a user-visible symlink must also drop the file behind `..data`, or the
// timestamped directory keeps an entry with no link to it. Upstream pathsToRemove
// walks that directory and removeUserVisiblePaths then fails removing a path that
// is already gone, so the first atomic write after a rollback errors out and
// leaves the superseded directory behind.
func Test_removeUnlistedFiles_realAtomicWriterRollbackSucceedsFirstTry(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	tsDir := writeLegacyAtomicLayout(t, dataPath, map[string]string{
		"tls.crt":        "cert-old",
		"service.pkcs12": "p12",
	})

	// Drop the keystore, as switching keystore support off does.
	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"tls.crt": []byte("cert-new"),
	}))

	// Now roll back to the atomic writer.
	require.NoError(t, clearInplaceArtifacts(dataPath))
	require.NoError(t, writeWithRealAtomicWriter(t, dataPath, map[string]string{"tls.crt": "cert-rollback"}),
		"the first atomic write after a rollback must succeed, not the second")

	assert.NoDirExists(t, tsDir,
		"the write failed before it could retire the superseded timestamped directory")

	got, err := os.ReadFile(filepath.Join(dataPath, "tls.crt"))
	require.NoError(t, err)
	assert.Equal(t, "cert-rollback", string(got))
}

// WriteFile is the CA-only path camanager uses. It must never touch anything
// but the named file, so that a certificate renewal running concurrently cannot
// be rolled back by a trust bundle update.
func Test_inplaceWriteStorage_WriteFile(t *testing.T) {
	meta := metadata.Metadata{VolumeID: "vol-id"}

	t.Run("creates the file on a fresh volume", func(t *testing.T) {
		s, dataPath := newTestInplaceStorage(t, "tls.crt")

		require.NoError(t, s.WriteFile(meta, "ca.crt", []byte("ca-1")))

		got, err := os.ReadFile(filepath.Join(dataPath, "ca.crt"))
		require.NoError(t, err)
		assert.Equal(t, "ca-1", string(got))
	})

	t.Run("skips identical content", func(t *testing.T) {
		s, dataPath := newTestInplaceStorage(t, "tls.crt")
		require.NoError(t, s.WriteFile(meta, "ca.crt", []byte("ca-1")))

		target := filepath.Join(dataPath, "ca.crt")
		sentinel := time.Now().Add(-time.Hour).Truncate(time.Second)
		require.NoError(t, os.Chtimes(target, sentinel, sentinel))

		require.NoError(t, s.WriteFile(meta, "ca.crt", []byte("ca-1")))

		after, err := os.Stat(target)
		require.NoError(t, err)
		assert.True(t, after.ModTime().Equal(sentinel),
			"an unchanged trust bundle was rewritten, waking every watcher for a no-op reload")
	})

	t.Run("leaves unrelated files alone", func(t *testing.T) {
		s, dataPath := newTestInplaceStorage(t, "tls.crt")
		require.NoError(t, s.WriteFiles(meta, map[string][]byte{
			"tls.crt":     []byte("cert-1"),
			"tls.key":     []byte("key-1"),
			"service.jks": []byte("jks"),
		}))

		before := map[string]uint64{}
		for _, name := range []string{"tls.crt", "tls.key", "service.jks"} {
			before[name] = inodeOf(t, filepath.Join(dataPath, name))
		}

		require.NoError(t, s.WriteFile(meta, "ca.crt", []byte("ca-1")))

		for name, want := range map[string]string{
			"tls.crt": "cert-1", "tls.key": "key-1", "service.jks": "jks",
		} {
			got, err := os.ReadFile(filepath.Join(dataPath, name))
			require.NoError(t, err)
			assert.Equal(t, want, string(got),
				"a CA-only write must not rewrite %q: the desired-state pruning and the "+
					"read-then-write of the keypair are exactly what races with a renewal", name)
			assert.Equal(t, before[name], inodeOf(t, filepath.Join(dataPath, name)),
				"inode of %q changed during a CA-only write", name)
		}
	})

	t.Run("writes through a legacy layout", func(t *testing.T) {
		s, dataPath := newTestInplaceStorage(t, "tls.crt")
		tsDir := writeLegacyAtomicLayout(t, dataPath, map[string]string{"ca.crt": "ca-old"})

		before := inodeOf(t, filepath.Join(tsDir, "ca.crt"))

		require.NoError(t, s.WriteFile(meta, "ca.crt", []byte("ca-new")))

		assert.Equal(t, before, inodeOf(t, filepath.Join(tsDir, "ca.crt")),
			"the trust bundle file was replaced instead of rewritten")
		got, err := os.ReadFile(filepath.Join(dataPath, "ca.crt"))
		require.NoError(t, err)
		assert.Equal(t, "ca-new", string(got))
	})

	t.Run("errors on a broken layout instead of delegating", func(t *testing.T) {
		s, dataPath := newTestInplaceStorage(t, "tls.crt")

		require.NoError(t, os.Symlink("..2026_01_01_00_00_00.1",
			filepath.Join(dataPath, atomicDataDirName)))
		require.NoError(t, os.Symlink(filepath.Join(atomicDataDirName, "ca.crt"),
			filepath.Join(dataPath, "ca.crt")))

		err := s.WriteFile(meta, "ca.crt", []byte("ca-1"))
		require.Error(t, err, "a broken `..data` chain cannot be written through")

		assert.Equal(t, 0, s.inner.(*fakeInnerStore).writeFilesCalls,
			"a single-file write must never reach the atomic writer: its payload is the "+
				"complete desired state, so a CA-only payload would delete the keypair")
	})
}

// The in-place writer bypasses the atomic writer, so it has to apply the same
// path validation itself; without it a payload name could escape the volume.
func Test_inplaceWriteStorage_WriteFiles_rejectsInvalidPayloadNames(t *testing.T) {
	for _, name := range []string{"../escape", "/abs", "a/../b", "", ".", "./", "..data", strings.Repeat("x", 256)} {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			s, dataPath := newTestInplaceStorage(t, "tls.crt")

			err := s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
				"tls.crt": []byte("cert"),
				name:      []byte("payload"),
			})
			require.Error(t, err, "payload name %q must be rejected", name)

			_, statErr := os.Lstat(filepath.Join(dataPath, "tls.crt"))
			assert.True(t, os.IsNotExist(statErr),
				"validation must reject the whole payload before anything is written")
			assert.Equal(t, 0, s.inner.(*fakeInnerStore).writeFilesCalls,
				"an invalid payload must not be handed to the atomic writer either")
		})
	}
}

// A nested payload name needs its parent directory created first, as upstream
// writePayloadToDir does.
func Test_inplaceWriteStorage_WriteFiles_nestedPayloadName(t *testing.T) {
	s, dataPath := newTestInplaceStorage(t, "tls.crt")

	require.NoError(t, s.WriteFiles(metadata.Metadata{VolumeID: "vol-id"}, map[string][]byte{
		"sub/ca.crt": []byte("ca"),
	}))

	assert.DirExists(t, filepath.Join(dataPath, "sub"), "the parent directory must be created")
	got, err := os.ReadFile(filepath.Join(dataPath, "sub", "ca.crt"))
	require.NoError(t, err)
	assert.Equal(t, "ca", string(got))
}

// The key is read once at construction, so the inner store must already have it
// set. A wrapper built before the key is assigned would silently ignore the
// fs-group volume attribute.
func Test_newInplaceWriteStorage_copiesFSGroupVolumeAttributeKey(t *testing.T) {
	s := newInplaceWriteStorage(&storage.Filesystem{FSGroupVolumeAttributeKey: "k"}, "tls.crt")

	assert.Equal(t, "k", s.fsGroupVolumeAttributeKey,
		"the inner store's FSGroupVolumeAttributeKey was not copied; fs-group ownership "+
			"would never be applied")
	assert.Equal(t, "tls.crt", s.certFileName)
}

func gidOf(t *testing.T, path string) int64 {
	t.Helper()

	info, err := os.Stat(path)
	require.NoError(t, err)
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok, "expected a *syscall.Stat_t for %q", path)

	return int64(stat.Gid)
}

func Test_ensureFileGroup_nilFSGroupIsANoOp(t *testing.T) {
	// A path that does not exist proves the nil check happens before the stat:
	// with no fs-group configured, ownership must not be touched or inspected.
	assert.NoError(t, ensureFileGroup(filepath.Join(t.TempDir(), "does-not-exist"), nil))
}

// twoOwnableGIDs returns two distinct gids the test process is allowed to chown
// a file it owns to. root may use any gid; anyone else is limited to the groups
// they are a member of, and the test is skipped when there are not two of them.
func twoOwnableGIDs(t *testing.T) (int64, int64) {
	t.Helper()

	if os.Geteuid() == 0 {
		return 1234, 4321
	}

	groups, err := os.Getgroups()
	require.NoError(t, err)
	if len(groups) < 2 {
		t.Skip("chowning a file needs either root or membership of two groups")
	}

	return int64(groups[0]), int64(groups[1])
}

func Test_ensureFileGroup_repairsChangedGroup(t *testing.T) {
	gidA, gidB := twoOwnableGIDs(t)

	target := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(target, []byte("ca"), 0o640))

	require.NoError(t, ensureFileGroup(target, &gidA))
	assert.Equal(t, gidA, gidOf(t, target))

	// Idempotent: a second call with the same gid must not fail.
	require.NoError(t, ensureFileGroup(target, &gidA))
	assert.Equal(t, gidA, gidOf(t, target))

	require.NoError(t, ensureFileGroup(target, &gidB))
	assert.Equal(t, gidB, gidOf(t, target))
}

// An existing file's ownership has to follow the volume's fs-group even when its
// contents do not change: a volume can be re-published with a different fsGroup
// while the certificate stays valid.
func Test_writeFileInPlace_repairsGroupOfExistingFile(t *testing.T) {
	gidA, gidB := twoOwnableGIDs(t)

	target := filepath.Join(t.TempDir(), "tls.crt")

	require.NoError(t, writeFileInPlace(target, []byte("cert-1"), &gidA))
	require.Equal(t, gidA, gidOf(t, target))

	t.Log("identical content, new fs-group")
	require.NoError(t, writeFileInPlace(target, []byte("cert-1"), &gidB))
	assert.Equal(t, gidB, gidOf(t, target),
		"the early return for identical content skipped the ownership repair")

	t.Log("new content, new fs-group")
	if os.Geteuid() != 0 {
		// Relax the 0440 mode the create set, so a non-root owner can reopen the
		// file for writing. The driver itself runs as root.
		require.NoError(t, os.Chmod(target, 0o640))
	}
	require.NoError(t, writeFileInPlace(target, []byte("cert-2"), &gidA))
	assert.Equal(t, gidA, gidOf(t, target),
		"a rewrite of an existing file skipped the ownership repair")
}

func Test_orderedWriteNames(t *testing.T) {
	tests := map[string]struct {
		files        []string
		certFileName string
		expOrder     []string
	}{
		"cert is written last": {
			files:        []string{"tls.key", "tls.crt", "ca.crt", "service.jks"},
			certFileName: "tls.crt",
			expOrder:     []string{"ca.crt", "service.jks", "tls.key", "tls.crt"},
		},
		"cert only": {
			files:        []string{"tls.crt"},
			certFileName: "tls.crt",
			expOrder:     []string{"tls.crt"},
		},
		"cert absent from the payload": {
			files:        []string{"tls.key", "ca.crt"},
			certFileName: "tls.crt",
			expOrder:     []string{"ca.crt", "tls.key"},
		},
		"no files": {
			files:        nil,
			certFileName: "tls.crt",
			expOrder:     []string{},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			files := map[string][]byte{}
			for _, file := range test.files {
				files[file] = []byte(file)
			}
			assert.Equal(t, test.expOrder, orderedWriteNames(files, test.certFileName))
		})
	}
}

func Test_inplaceWriteStorage_fsGroupForMetadata(t *testing.T) {
	const attrKey = "csi.cert-manager.athenz.io/fs-group"

	tests := map[string]struct {
		volumeContext    map[string]string
		volumeMountGroup string
		expFSGroup       *int64
		// expErrContains, when set, is a substring the error must contain. The
		// value can come from either source, so an error has to name the one the
		// operator actually set rather than always blaming the attribute key.
		expErrContains string
	}{
		"valid volume attribute": {
			volumeContext: map[string]string{attrKey: "1234"},
			expFSGroup:    ptrInt64(1234),
		},
		"attribute absent": {
			volumeContext: map[string]string{"other": "1234"},
			expFSGroup:    nil,
		},
		"attribute empty falls back to the volume mount group": {
			volumeContext:    map[string]string{attrKey: ""},
			volumeMountGroup: "4321",
			expFSGroup:       ptrInt64(4321),
		},
		"not a number": {
			volumeContext:  map[string]string{attrKey: "not-a-gid"},
			expErrContains: `volume attribute "` + attrKey + `"`,
		},
		"not a number in the volume mount group": {
			volumeMountGroup: "not-a-gid",
			expErrContains:   "volume mount group",
		},
		"zero is out of range": {
			volumeContext:  map[string]string{attrKey: "0"},
			expErrContains: `volume attribute "` + attrKey + `"`,
		},
		"above the maximum gid": {
			volumeContext:  map[string]string{attrKey: "4294967296"},
			expErrContains: `volume attribute "` + attrKey + `"`,
		},
		"out of range in the volume mount group": {
			volumeMountGroup: "4294967296",
			expErrContains:   "volume mount group",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := &inplaceWriteStorage{fsGroupVolumeAttributeKey: attrKey}

			fsGroup, err := s.fsGroupForMetadata(metadata.Metadata{
				VolumeContext:    test.volumeContext,
				VolumeMountGroup: test.volumeMountGroup,
			})
			if test.expErrContains != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.expErrContains,
					"the error must name the field the gid was read from, not always the "+
						"volume attribute key")
				return
			}

			require.NoError(t, err)
			if test.expFSGroup == nil {
				assert.Nil(t, fsGroup)
				return
			}
			require.NotNil(t, fsGroup)
			assert.Equal(t, *test.expFSGroup, *fsGroup)
		})
	}
}

func ptrInt64(i int64) *int64 { return &i }
