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
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeInnerStore stands in for *storage.Filesystem. The real one cannot be used
// in a unit test: storage.NewFilesystem mounts a tmpfs, and the fields needed to
// build one by hand are unexported.
type fakeInnerStore struct {
	dataPath string

	// writeFilesCalls counts delegations to the inner (atomic) writer. The
	// in-place writer is expected to delegate only when the existing symlink
	// layout is broken beyond in-place repair.
	writeFilesCalls int
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

// WriteFiles records the delegation. On a healthy volume the in-place writer
// does all writing itself; it only hands over to the inner atomic writer to
// rebuild a volume whose symlink layout is broken.
func (f *fakeInnerStore) WriteFiles(metadata.Metadata, map[string][]byte) error {
	f.writeFilesCalls++
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
	before, err := os.Stat(target)
	require.NoError(t, err)

	// Deliberately no makeWritableForRewrite: an identical write must return
	// before even opening the file, so the 0440 mode never gets in the way.
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, s.WriteFiles(meta, map[string][]byte{"tls.crt": []byte("same")}))

	after, err := os.Stat(target)
	require.NoError(t, err)
	assert.Equal(t, before.ModTime(), after.ModTime(),
		"identical content was rewritten; the pod's watcher would be woken for a no-op reload")
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
		expErr           bool
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
			volumeContext: map[string]string{attrKey: "not-a-gid"},
			expErr:        true,
		},
		"zero is out of range": {
			volumeContext: map[string]string{attrKey: "0"},
			expErr:        true,
		},
		"above the maximum gid": {
			volumeContext: map[string]string{attrKey: "4294967296"},
			expErr:        true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			s := &inplaceWriteStorage{fsGroupVolumeAttributeKey: attrKey}

			fsGroup, err := s.fsGroupForMetadata(metadata.Metadata{
				VolumeContext:    test.volumeContext,
				VolumeMountGroup: test.volumeMountGroup,
			})
			if test.expErr {
				assert.Error(t, err)
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
