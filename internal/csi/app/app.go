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

package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/AthenZ/csi-driver-athenz/internal/csi/app/options"
	"github.com/AthenZ/csi-driver-athenz/internal/csi/driver"
	"github.com/AthenZ/csi-driver-athenz/internal/csi/rootca"
	"github.com/AthenZ/csi-driver-athenz/internal/version"
)

const (
	helpOutput = "A cert-manager CSI driver for requesting Athenz certificates from cert-manager on behalf of the mounting Pod."
)

// NewCommand returns an new command instance of the CSI driver component of csi-driver-athenz.
func NewCommand(ctx context.Context) *cobra.Command {
	opts := options.New()

	cmd := &cobra.Command{
		Use:   "csi-driver-athenz",
		Short: helpOutput,
		Long:  helpOutput,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return opts.Complete()
		},

		RunE: func(cmd *cobra.Command, args []string) error {
			log := opts.Logr.WithName("main")
			log.Info("Starting driver", "version", version.VersionInfo())

			var rootCA rootca.Interface
			if len(opts.Volume.SourceCABundleFile) > 0 {
				log.Info("using CA root bundle", "filepath", opts.Volume.SourceCABundleFile)

				var err error
				rootCA, err = rootca.NewFile(ctx, opts.Logr, opts.Volume.SourceCABundleFile)
				if err != nil {
					return fmt.Errorf("failed to build root CA: %w", err)
				}
			} else {
				log.Info("propagating root CA bundle disabled")
			}

			annotations := map[string]string{}
			for key, value := range opts.CertManager.CertificateRequestAnnotations {
				if strings.HasPrefix(key, "csi.cert-manager.athenz.io") {
					log.Error(nil, "custom annotations must not begin with csi.cert-manager.athenz.io, skipping %s", key)
				} else {
					annotations[key] = value
				}
			}

			driver, err := driver.New(ctx, opts.Logr, driver.Options{
				DriverName: opts.DriverName,
				NodeID:     opts.Driver.NodeID,
				Endpoint:   opts.Driver.Endpoint,
				DataRoot:   opts.Driver.DataRoot,

				RestConfig: opts.RestConfig,

				TrustDomain:                   opts.CertManager.TrustDomain,
				CertificateRequestAnnotations: annotations,
				CertificateRequestDuration:    opts.CertManager.CertificateRequestDuration,
				IssuerRef:                     opts.CertManager.IssuerRef,

				CertificateFileName: opts.Volume.CertificateFileName,
				KeyFileName:         opts.Volume.KeyFileName,
				CAFileName:          opts.Volume.CAFileName,
				KeystoreEnabled:     opts.Volume.KeystoreEnabled,
				KeystoreFileName:    opts.Volume.KeystoreFileName,
				JKSFileName:         opts.Volume.JKSFileName,
				KeystorePassword:    opts.Volume.KeystorePassword,
				KeystoreAlias:       opts.Volume.KeystoreAlias,
				WriteMode:           opts.Volume.WriteMode,

				RootCAs: rootCA,

				ZTS:             opts.Athenz.ZTS,
				CACertFile:      opts.Athenz.CACertFile,
				ProviderPrefix:  opts.Athenz.ProviderPrefix,
				DNSDomains:      opts.Athenz.DNSDomains,
				CertCountryName: opts.Athenz.CertCountryName,
				CertOrgName:     opts.Athenz.CertOrgName,
				CloudProvider:   opts.Athenz.CloudProvider,
				CloudRegion:     opts.Athenz.CloudRegion,
			})
			if err != nil {
				return err
			}

			log.Info("starting Athenz CSI driver...")

			return driver.Run(ctx)
		},
	}

	opts.Prepare(cmd)

	return cmd
}
