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
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cert-manager/csi-lib/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/klog/v2/klogr"

	"github.com/AthenZ/csi-driver-athenz/internal/csi/rootca"
)

// updateDeadline is generous on purpose: the assertions here are about whether
// run() dispatches an update at all, not about how quickly it does so, and a
// tight deadline only produces flakes on a loaded CI machine.
const updateDeadline = 5 * time.Second

// fakeSubscribableRootCAs hands run() an event channel the test drives directly
// and reports when run() has subscribed.
//
// rootca.NewMemory, which this test used to use, broadcasts only to the
// subscribers that exist at the moment it receives a new bundle, and run()
// subscribes from inside its own goroutine. An event published before that
// subscription exists is silently dropped, and the test cannot observe when it
// is safe to publish - which is the second half of this test's flakiness.
type fakeSubscribableRootCAs struct {
	events     chan struct{}
	subscribed chan struct{}
	once       sync.Once
}

func (f *fakeSubscribableRootCAs) CertificatesPEM() []byte { return nil }

func (f *fakeSubscribableRootCAs) Subscribe() <-chan struct{} {
	f.once.Do(func() { close(f.subscribed) })
	return f.events
}

var _ rootca.Interface = &fakeSubscribableRootCAs{}

func Test_manageCAFiles(t *testing.T) {
	ctx, cancel := context.WithCancel(context.TODO())
	t.Cleanup(func() {
		cancel()
	})

	rootCAs := &fakeSubscribableRootCAs{
		events:     make(chan struct{}),
		subscribed: make(chan struct{}),
	}
	c := &camanager{
		log:     klogr.New(),
		rootCAs: rootCAs,
	}

	// updateRootCAFilesFn is installed once, before run() starts, and takes its
	// behaviour from a channel. Reassigning the field after run() is already
	// executing - as this test used to - is a data race on the field: run() reads
	// it from its own goroutine.
	behaviours := make(chan func() error, 4)
	c.updateRootCAFilesFn = func() error {
		select {
		case behaviour := <-behaviours:
			return behaviour()
		case <-ctx.Done():
			return nil
		}
	}

	t.Log("starting manageCAFiles()")
	go func() {
		c.run(ctx, time.Millisecond*5)
	}()

	t.Log("waiting for run() to subscribe to root CA events")
	select {
	case <-rootCAs.subscribed:
	case <-time.After(updateDeadline):
		t.Fatal("run() never subscribed to root CA events")
	}

	t.Log("if root CAs update happens, expect updateRootCAFilesFn() to be called")
	calledChan := make(chan struct{})
	behaviours <- func() error {
		t.Log("updateRootCAFilesFn() called")
		close(calledChan)
		return nil
	}

	t.Log("sending root CAs event")
	rootCAs.events <- struct{}{}
	t.Log("waiting for the call")
	select {
	case <-calledChan:
		break
	case <-time.After(updateDeadline):
		assert.Fail(t, "updateRootCAFilesFn() was not called in time")
	}

	t.Log("should call updateRootCAFilesFn() again if it fails")
	calledTwiceChan := make(chan struct{})
	behaviours <- func() error {
		t.Log("returning error from updateRootCAFilesFn()")
		return errors.New("this is an error")
	}
	behaviours <- func() error {
		t.Log("returning nil from updateRootCAFilesFn()")
		close(calledTwiceChan)
		return nil
	}

	t.Log("sending another root CAs event")
	rootCAs.events <- struct{}{}
	t.Log("waiting for two calls")
	select {
	case <-calledTwiceChan:
		break
	case <-time.After(updateDeadline):
		assert.Fail(t, "updateRootCAFilesFn() was not called twice in time")
	}
}

// fakeRootCAs is a fixed trust bundle. rootca.NewMemory would do, but its
// contents are only set asynchronously from a channel.
type fakeRootCAs struct {
	pem []byte
}

func (f *fakeRootCAs) CertificatesPEM() []byte    { return f.pem }
func (f *fakeRootCAs) Subscribe() <-chan struct{} { return make(chan struct{}) }

var _ rootca.Interface = &fakeRootCAs{}

// fakeCAStore implements the atomic-dir surface: only whole-payload writes, with
// the atomic writer's desired-state semantics.
type fakeCAStore struct {
	volumeIDs []string
	files     map[string]map[string][]byte

	// writeFilesPayloads records every whole-volume write.
	writeFilesPayloads []map[string][]byte
}

func newFakeCAStore(volumeID string, files map[string][]byte) *fakeCAStore {
	return &fakeCAStore{
		volumeIDs: []string{volumeID},
		files:     map[string]map[string][]byte{volumeID: files},
	}
}

func (f *fakeCAStore) ListVolumes() ([]string, error) { return f.volumeIDs, nil }

func (f *fakeCAStore) ReadMetadata(volumeID string) (metadata.Metadata, error) {
	return metadata.Metadata{VolumeID: volumeID}, nil
}

func (f *fakeCAStore) ReadFile(volumeID, name string) ([]byte, error) {
	data, ok := f.files[volumeID][name]
	if !ok {
		return nil, fmt.Errorf("no such file %q on volume %q", name, volumeID)
	}
	return data, nil
}

func (f *fakeCAStore) WriteFiles(meta metadata.Metadata, files map[string][]byte) error {
	f.writeFilesPayloads = append(f.writeFilesPayloads, files)

	// The atomic writer treats the payload as the complete desired contents of
	// the volume and deletes everything else.
	replaced := map[string][]byte{}
	for name, data := range files {
		replaced[name] = data
	}
	f.files[meta.VolumeID] = replaced

	return nil
}

var _ volumeStore = &fakeCAStore{}

// fakeSingleFileCAStore adds the single-file write the in-place store provides.
type fakeSingleFileCAStore struct {
	*fakeCAStore

	// singleWrites records every CA-only write, in order.
	singleWrites []fakeSingleWrite
}

type fakeSingleWrite struct {
	volumeID string
	name     string
	data     []byte
}

func (f *fakeSingleFileCAStore) WriteFile(meta metadata.Metadata, name string, data []byte) error {
	f.singleWrites = append(f.singleWrites, fakeSingleWrite{meta.VolumeID, name, data})
	f.files[meta.VolumeID][name] = data

	return nil
}

var (
	_ volumeStore      = &fakeSingleFileCAStore{}
	_ singleFileWriter = &fakeSingleFileCAStore{}
)

func newTestCAManager(store volumeStore, caPEM string) *camanager {
	return &camanager{
		log:          klogr.New(),
		store:        store,
		rootCAs:      &fakeRootCAs{pem: []byte(caPEM)},
		certFileName: "tls.crt",
		keyFileName:  "tls.key",
		caFileName:   "ca.crt",
	}
}

// In in-place mode the trust bundle is published on its own. Rewriting the
// certificate and key from a snapshot read moments earlier silently rolls back a
// renewal that landed in between, while the renewal's metadata records success.
func Test_updateRootCAFiles_inPlaceWritesOnlyTheCAFile(t *testing.T) {
	inner := newFakeCAStore("vol-id", map[string][]byte{
		"tls.crt": []byte("cert-1"),
		"tls.key": []byte("key-1"),
		"ca.crt":  []byte("ca-old"),
	})
	store := &fakeSingleFileCAStore{fakeCAStore: inner}

	require.NoError(t, newTestCAManager(store, "ca-new").updateRootCAFiles())

	assert.Empty(t, inner.writeFilesPayloads,
		"a store that can write a single file must never take the whole-payload path: reading "+
			"the keypair and writing it back races with certificate renewal")

	require.Len(t, store.singleWrites, 1)
	assert.Equal(t, fakeSingleWrite{"vol-id", "ca.crt", []byte("ca-new")}, store.singleWrites[0])

	assert.Equal(t, []byte("cert-1"), inner.files["vol-id"]["tls.crt"],
		"the certificate must not be touched by a trust bundle update")
	assert.Equal(t, []byte("key-1"), inner.files["vol-id"]["tls.key"],
		"the private key must not be touched by a trust bundle update")
}

// The certificate and key are not read at all in in-place mode, so a volume
// whose keypair cannot be read still gets its trust bundle updated.
func Test_updateRootCAFiles_inPlaceDoesNotReadTheKeypair(t *testing.T) {
	inner := newFakeCAStore("vol-id", map[string][]byte{"ca.crt": []byte("ca-old")})
	store := &fakeSingleFileCAStore{fakeCAStore: inner}

	require.NoError(t, newTestCAManager(store, "ca-new").updateRootCAFiles())

	require.Len(t, store.singleWrites, 1)
	assert.Equal(t, []byte("ca-new"), inner.files["vol-id"]["ca.crt"])
}

func Test_updateRootCAFiles_skipsUnchangedCAData(t *testing.T) {
	t.Run("in-place", func(t *testing.T) {
		inner := newFakeCAStore("vol-id", map[string][]byte{
			"tls.crt": []byte("cert-1"),
			"tls.key": []byte("key-1"),
			"ca.crt":  []byte("ca-same"),
		})
		store := &fakeSingleFileCAStore{fakeCAStore: inner}

		require.NoError(t, newTestCAManager(store, "ca-same").updateRootCAFiles())

		assert.Empty(t, store.singleWrites, "an unchanged trust bundle must not be rewritten")
		assert.Empty(t, inner.writeFilesPayloads)
	})

	t.Run("atomic-dir", func(t *testing.T) {
		store := newFakeCAStore("vol-id", map[string][]byte{
			"tls.crt": []byte("cert-1"),
			"tls.key": []byte("key-1"),
			"ca.crt":  []byte("ca-same"),
		})

		require.NoError(t, newTestCAManager(store, "ca-same").updateRootCAFiles())

		assert.Empty(t, store.writeFilesPayloads, "an unchanged trust bundle must not be rewritten")
	})
}

// The atomic-dir rollback keeps the original behaviour: the atomic writer
// deletes every file missing from its payload, so all three have to be written.
func Test_updateRootCAFiles_atomicDirWritesAllThreeFiles(t *testing.T) {
	store := newFakeCAStore("vol-id", map[string][]byte{
		"tls.crt": []byte("cert-1"),
		"tls.key": []byte("key-1"),
		"ca.crt":  []byte("ca-old"),
	})

	require.NoError(t, newTestCAManager(store, "ca-new").updateRootCAFiles())

	require.Len(t, store.writeFilesPayloads, 1)
	assert.Equal(t, map[string][]byte{
		"tls.crt": []byte("cert-1"),
		"tls.key": []byte("key-1"),
		"ca.crt":  []byte("ca-new"),
	}, store.writeFilesPayloads[0],
		"the atomic writer prunes anything missing from its payload, so the keypair has to be "+
			"written back alongside the new trust bundle")
}

// Without a single-file writer the keypair has to be readable, and a volume that
// has not been written yet must surface an error rather than publish a partial
// payload the atomic writer would prune the rest of.
func Test_updateRootCAFiles_atomicDirErrorsWhenKeypairIsUnreadable(t *testing.T) {
	store := newFakeCAStore("vol-id", map[string][]byte{"ca.crt": []byte("ca-old")})

	err := newTestCAManager(store, "ca-new").updateRootCAFiles()
	require.Error(t, err)
	assert.Empty(t, store.writeFilesPayloads)
}
