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

package options

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// Test_loadKeystorePassword_Precedence covers the resolution order:
//  1. KEYSTORE_PASSWORD env var (when non-empty)
//  2. --keystore-password-file contents
//  3. built-in default "changeit"
//
// It also covers the disabled-feature short-circuit and the empty-file
// fail-fast behaviour.
func Test_loadKeystorePassword_Precedence(t *testing.T) {
	writeFile := func(t *testing.T, content string) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "password")
		require.NoError(t, os.WriteFile(path, []byte(content), 0600))
		return path
	}

	t.Run("disabled-skips-resolution", func(t *testing.T) {
		t.Setenv(KeystorePasswordEnvVar, "from-env")
		o := &Options{}
		o.Volume.KeystoreEnabled = false
		o.Volume.KeystorePasswordFile = writeFile(t, "from-file")
		require.NoError(t, o.loadKeystorePassword())
		require.Empty(t, o.Volume.KeystorePassword,
			"disabled feature must not populate KeystorePassword from any source")
	})

	t.Run("env-wins-over-file", func(t *testing.T) {
		t.Setenv(KeystorePasswordEnvVar, "from-env")
		o := &Options{}
		o.Volume.KeystoreEnabled = true
		o.Volume.KeystorePasswordFile = writeFile(t, "from-file")
		require.NoError(t, o.loadKeystorePassword())
		require.Equal(t, "from-env", o.Volume.KeystorePassword)
	})

	t.Run("file-when-env-unset", func(t *testing.T) {
		// Setenv with "" and then unsetting would still differ from "unset";
		// rely on a fresh process env: parent test does not set the var.
		o := &Options{}
		o.Volume.KeystoreEnabled = true
		o.Volume.KeystorePasswordFile = writeFile(t, "from-file\n")
		require.NoError(t, o.loadKeystorePassword())
		require.Equal(t, "from-file", o.Volume.KeystorePassword,
			"trailing newline from `echo > file` must be stripped")
	})

	t.Run("env-empty-falls-through-to-file", func(t *testing.T) {
		t.Setenv(KeystorePasswordEnvVar, "")
		o := &Options{}
		o.Volume.KeystoreEnabled = true
		o.Volume.KeystorePasswordFile = writeFile(t, "from-file")
		require.NoError(t, o.loadKeystorePassword())
		require.Equal(t, "from-file", o.Volume.KeystorePassword,
			"an env var set to the empty string must be treated as unset")
	})

	t.Run("default-when-nothing-set", func(t *testing.T) {
		o := &Options{}
		o.Volume.KeystoreEnabled = true
		require.NoError(t, o.loadKeystorePassword())
		require.Equal(t, DefaultKeystorePassword, o.Volume.KeystorePassword)
	})

	t.Run("explicit-empty-file-is-fatal", func(t *testing.T) {
		o := &Options{}
		o.Volume.KeystoreEnabled = true
		o.Volume.KeystorePasswordFile = writeFile(t, "")
		err := o.loadKeystorePassword()
		require.Error(t, err)
		require.Contains(t, err.Error(), "is empty")
	})

	t.Run("missing-file-is-fatal", func(t *testing.T) {
		o := &Options{}
		o.Volume.KeystoreEnabled = true
		o.Volume.KeystorePasswordFile = filepath.Join(t.TempDir(), "does-not-exist")
		err := o.loadKeystorePassword()
		require.Error(t, err)
		require.Contains(t, err.Error(), "reading --keystore-password-file")
	})
}

// Test_validateWriteMode covers the accepted --volume-write-mode values and the
// fail-fast on anything else, so a typo cannot silently leave the driver on a
// write mode the operator did not ask for.
func Test_validateWriteMode(t *testing.T) {
	t.Run("in-place", func(t *testing.T) {
		o := &Options{}
		o.Volume.WriteMode = WriteModeInPlace
		require.NoError(t, o.validateWriteMode())
	})

	t.Run("atomic-dir", func(t *testing.T) {
		o := &Options{}
		o.Volume.WriteMode = WriteModeAtomicDir
		require.NoError(t, o.validateWriteMode())
	})

	t.Run("unknown-is-fatal", func(t *testing.T) {
		o := &Options{}
		o.Volume.WriteMode = "atomic"
		err := o.validateWriteMode()
		require.Error(t, err)
		require.Contains(t, err.Error(), `invalid --volume-write-mode "atomic"`)
	})
}
