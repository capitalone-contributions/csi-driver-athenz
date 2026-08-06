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
	"fmt"
	"os"
	"strings"
	"time"

	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/spf13/pflag"

	"github.com/AthenZ/csi-driver-athenz/internal/flags"

	_ "k8s.io/client-go/plugin/pkg/client/auth"
)

// DefaultKeystorePassword is the well-known Java keystore default used when
// neither KeystorePasswordEnvVar nor --keystore-password-file is configured.
const DefaultKeystorePassword = "changeit"

// KeystorePasswordEnvVar is the environment variable read at startup for the
// keystore password. When set, it takes precedence over
// --keystore-password-file. Intentionally not exposed as a CLI flag to avoid
// leaking the password via `ps`.
const KeystorePasswordEnvVar = "KEYSTORE_PASSWORD"

// WriteModeInPlace and WriteModeAtomicDir are the accepted values of
// --volume-write-mode. They mirror the driver package's constants of the same
// name, duplicated here so flag parsing stays independent of the driver
// package, as DefaultKeystorePassword already is.
const (
	// WriteModeInPlace rewrites the existing volume files so their inodes, and
	// therefore the inotify watches consumers such as istio-agent hold on them,
	// survive a certificate renewal.
	WriteModeInPlace = "in-place"

	// WriteModeAtomicDir restores the upstream csi-lib timestamped-directory
	// writer. Rollback path only.
	WriteModeAtomicDir = "atomic-dir"
)

// Options are the CSI Driver flag options.
type Options struct {
	*flags.Flags

	// Driver are options specific to the driver itself.
	Driver OptionsDriver

	// CertManager are options specific to created cert-manager
	// CertificateRequests.
	CertManager OptionsCertManager

	// Volume are options specific to mounted volumes.
	Volume OptionsVolume

	// Athenz are options specific to Athenz.
	Athenz OptionsAthenz
}

// OptionsDriver are options specific to the CSI driver itself.
type OptionsDriver struct {
	// NodeID is the name of the node the driver is running on.
	NodeID string

	// DataRoot is the path to the in-memory data directory used to store data.
	DataRoot string

	// Endpoint is the endpoint which is used to listen for gRPC requests.
	Endpoint string
}

// OptionsCertManager is options specific to cert-manager CertificateRequests.
type OptionsCertManager struct {
	// TrustDomain is the trust domain of this SPIFFE PKI. The TrustDomain will
	// appear in signed certificate's URI SANs.
	TrustDomain string

	// CertificateRequestAnnotations are annotations that are to be added to certificate requests created by the driver
	CertificateRequestAnnotations map[string]string

	// CertificateRequestDuration is the duration CertificateRequests will be
	// requested with.
	CertificateRequestDuration time.Duration

	// IssuerRef is the IssuerRef used when creating CertificateRequests.
	IssuerRef cmmeta.ObjectReference
}

// OptionsVolume is options specific to mounted volumes.
type OptionsVolume struct {
	// CertificateFileName is the name of the file that the signed certificate
	// will be written to inside the Pod's volume.
	CertificateFileName string

	// KeyFileName is the name of the file that the private key will be written
	// to inside the Pod's volume.
	// Default to `tls.key` if empty.
	KeyFileName string

	// FileName is the name of the file that the root CA certificates will be
	// written to inside the Pod's volume. Ignored if SourceCABundleFile is not
	// defined.
	CAFileName string

	// SourceCABundleFile is the file path location containing a bundle of PEM
	// encoded X.509 root CA certificates that will be written to managed volumes
	// at the CSICAFileName path. No CAs will be written if this is empty.
	SourceCABundleFile string

	// KeystoreEnabled is the master switch for PKCS12 / JKS keystore
	// provisioning. Disabled by default; opt in to write PKCS12 / JKS files
	// alongside the PEM identity files.
	KeystoreEnabled bool

	// KeystoreFileName is the file name used for the PKCS12 keystore written
	// into the Pod's volume. Has no effect unless KeystoreEnabled is true.
	KeystoreFileName string

	// JKSFileName is the file name used for the JKS keystore written into the
	// Pod's volume. Has no effect unless KeystoreEnabled is true.
	JKSFileName string

	// KeystorePasswordFile is a file path whose contents are used as the
	// password to encrypt the PKCS12 / JKS keystores. Ignored if the
	// KeystorePasswordEnvVar environment variable is set; otherwise, when
	// empty, the well-known Java default `changeit` is used. The password is
	// intentionally not exposed as a plain CLI flag to avoid leaking it
	// via `ps`.
	KeystorePasswordFile string

	// KeystorePassword is the password used to encrypt the PKCS12 / JKS
	// keystores. Resolved during option completion from (in order of
	// precedence) the KeystorePasswordEnvVar environment variable, the
	// KeystorePasswordFile contents, or the built-in default. Not set
	// directly by a flag.
	KeystorePassword string

	// KeystoreAlias is the alias used for the private key entry inside the
	// JKS keystore.
	KeystoreAlias string

	// WriteMode selects how certificate data is written into the Pod's volume.
	// One of WriteModeInPlace (default) or WriteModeAtomicDir; validated during
	// option completion.
	WriteMode string
}

// OptionsAthenz is options specific to Athenz.
type OptionsAthenz struct {
	// ZTS is the URL of the ZTS server.
	ZTS string

	// Provider prefix for the backend provider in ZTS which is responsible for verifying and
	// issuing the identity.
	ProviderPrefix string

	// Athenz CA certificate file path.
	CACertFile string

	// DNS domains to be added in the service identity certificate.
	DNSDomains string

	// Country name in the service identity certificate.
	CertCountryName string

	// Organization name in the service identity certificate.
	CertOrgName string

	// Cloud provider where service is running.
	CloudProvider string

	// Cloud region where service is running.
	CloudRegion string
}

func New() *Options {
	o := new(Options)
	o.Flags = flags.New().
		Add("Driver", o.addDriverFlags).
		Add("cert-manager", o.addCertManagerFlags).
		Add("Volume", o.addVolumeFlags).
		Add("Athenz", o.addAthenzFlags)

	return o
}

func (o *Options) addDriverFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Driver.NodeID, "node-id", "",
		"Name of the node the driver is running on.")
	fs.StringVar(&o.Driver.DataRoot, "data-root", "",
		"Path to the in-memory data directory used to store data.")
	fs.StringVar(&o.Driver.Endpoint, "endpoint", "",
		"Path to the unix socket used to listen for gRPC requests.")
}

func (o *Options) addCertManagerFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.CertManager.TrustDomain, "trust-domain", "cluster.local",
		"The trust domain that will be requested for on created CertificateRequests.")
	fs.DurationVar(&o.CertManager.CertificateRequestDuration, "certificate-request-duration", time.Hour,
		"The duration that created CertificateRequests will use.")

	fs.StringToStringVar(&o.CertManager.CertificateRequestAnnotations, "extra-certificate-request-annotations", map[string]string{},
		"Comma-separated list of extra annotations to add to certificate requests e.g '--extra-certificate-request-annotations=hello=world,test=annotation'")

	fs.StringVar(&o.CertManager.IssuerRef.Name, "issuer-name", "athenz-ca",
		"Name of the issuer that CertificateRequests will be created for.")
	fs.StringVar(&o.CertManager.IssuerRef.Kind, "issuer-kind", "ClusterIssuer",
		"Kind of the issuer that CertificateRequests will be created for.")
	fs.StringVar(&o.CertManager.IssuerRef.Group, "issuer-group", "athenz-issuer.athenz.io",
		"Group of the issuer that CertificateRequests will be created for.")
}

func (o *Options) addVolumeFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Volume.CertificateFileName, "file-name-certificate", "tls.crt",
		"The file name that signed certificates will be written to within the pod's volume directory.")
	fs.StringVar(&o.Volume.KeyFileName, "file-name-key", "tls.key",
		"The file name that the certificate's private key will be written to within the pod's volume directory.")
	fs.StringVar(&o.Volume.CAFileName, "file-name-ca", "ca.crt",
		"The file name that the certificate's private key will be written to within the pod's volume directory.")

	fs.StringVar(&o.Volume.SourceCABundleFile, "source-ca-bundle", "",
		"File path that is read by the driver which will be written to all managed "+
			"volumes to the file location inside volumes defined in --file-name-ca. If "+
			"undefined, no CA file is written to volumes.")

	fs.BoolVar(&o.Volume.KeystoreEnabled, "enable-keystore", false,
		"Enable provisioning of PKCS12 and JKS keystores alongside the PEM "+
			"identity files. When false (default), no keystores are written and "+
			"the --file-name-keystore / --file-name-jks / --keystore-password / "+
			"--keystore-alias flags have no effect.")
	fs.StringVar(&o.Volume.KeystoreFileName, "file-name-keystore", "service.pkcs12",
		"The file name of the PKCS12 keystore written into the pod's volume. "+
			"Requires --enable-keystore. The keystore contains the private key "+
			"and leaf certificate using the legacy PKCS12 encoding to mirror the "+
			"on-disk format produced by `openssl pkcs12 -export -noiter -nomaciter`. "+
			"Set to an empty string to skip PKCS12 keystore generation while still "+
			"writing the JKS keystore.")
	fs.StringVar(&o.Volume.JKSFileName, "file-name-jks", "service.jks",
		"The file name of the JKS keystore written into the pod's volume. "+
			"Requires --enable-keystore. Set to an empty string to skip JKS "+
			"keystore generation while still writing the PKCS12 keystore.")
	fs.StringVar(&o.Volume.KeystorePasswordFile, "keystore-password-file", "",
		"File path whose contents are used as the password to encrypt the "+
			"PKCS12 and JKS keystores. Ignored when the KEYSTORE_PASSWORD "+
			"environment variable is set (env wins). When both are unset, the "+
			"well-known Java default `changeit` is used. The password is "+
			"never accepted as a plain CLI flag, to avoid exposing it via `ps`. "+
			"Requires --enable-keystore.")
	fs.StringVar(&o.Volume.KeystoreAlias, "keystore-alias", "service",
		"Alias used for the private key entry inside the JKS keystore. "+
			"Requires --enable-keystore.")

	fs.StringVar(&o.Volume.WriteMode, "volume-write-mode", WriteModeInPlace,
		"How certificate data is written into the pod's volume. `in-place` "+
			"(default) rewrites the existing files, keeping their inodes so "+
			"inotify watches held by consumers such as istio-agent survive a "+
			"renewal. `atomic-dir` restores the upstream csi-lib writer, which "+
			"replaces the files via a new timestamped directory on every write "+
			"and so silently breaks those watches; it is provided as a rollback "+
			"path only. Note that `in-place` rewrites are not atomic against "+
			"concurrent readers: a reader that catches the window between the "+
			"write and the truncate must re-read on the next inotify event, as "+
			"istio-agent does.")
}

func (o *Options) addAthenzFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.Athenz.ZTS, "zts", "", "URL of the ZTS server.")
	fs.StringVar(&o.Athenz.ProviderPrefix, "provider-prefix", "", "Provider prefix for the backend provider in ZTS which is responsible for verifying and issuing the identity.")
	fs.StringVar(&o.Athenz.CACertFile, "ca-cert-file", "", "Athenz CA certificate file path.")
	fs.StringVar(&o.Athenz.DNSDomains, "dns-domains", "", "DNS domains to be added in the service identity certificate. Multiple domains can be specified by separating them with commas.")
	fs.StringVar(&o.Athenz.CertCountryName, "cert-country-name", "US", "Country name in the service identity certificate.")
	fs.StringVar(&o.Athenz.CertOrgName, "cert-org-name", "Athenz", "Organization name in the service identity certificate.")
	fs.StringVar(&o.Athenz.CloudProvider, "cloud-provider", "", "Cloud provider where the driver is running.")
	fs.StringVar(&o.Athenz.CloudRegion, "cloud-region", "", "Cloud region where the driver is running.")
}

// Complete extends the embedded Flags.Complete with options-specific
// finalisation, in particular reading the keystore password from disk so it
// is not exposed via process arguments.
func (o *Options) Complete() error {
	if err := o.Flags.Complete(); err != nil {
		return err
	}
	if err := o.validateWriteMode(); err != nil {
		return err
	}
	return o.loadKeystorePassword()
}

// validateWriteMode rejects an unrecognised --volume-write-mode at startup,
// rather than letting the driver silently fall back to a write mode the
// operator did not ask for.
func (o *Options) validateWriteMode() error {
	switch o.Volume.WriteMode {
	case WriteModeInPlace, WriteModeAtomicDir:
		return nil
	default:
		return fmt.Errorf("invalid --volume-write-mode %q, must be one of %q or %q",
			o.Volume.WriteMode, WriteModeInPlace, WriteModeAtomicDir)
	}
}

// loadKeystorePassword resolves Volume.KeystorePassword using the following
// precedence (highest to lowest):
//
//  1. KeystorePasswordEnvVar environment variable, if non-empty
//  2. KeystorePasswordFile contents (trailing CR/LF stripped), if the flag is set
//  3. DefaultKeystorePassword built-in fallback (`changeit`)
//
// An explicitly-set but empty file is treated as a startup error so a
// misconfigured Secret mount fails fast rather than silently using a blank
// password.
func (o *Options) loadKeystorePassword() error {
	if !o.Volume.KeystoreEnabled {
		return nil
	}

	if envPassword, ok := os.LookupEnv(KeystorePasswordEnvVar); ok && envPassword != "" {
		o.Volume.KeystorePassword = envPassword
		return nil
	}

	if o.Volume.KeystorePasswordFile == "" {
		o.Volume.KeystorePassword = DefaultKeystorePassword
		return nil
	}

	data, err := os.ReadFile(o.Volume.KeystorePasswordFile)
	if err != nil {
		return fmt.Errorf("reading --keystore-password-file %q: %w",
			o.Volume.KeystorePasswordFile, err)
	}
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return fmt.Errorf("--keystore-password-file %q is empty",
			o.Volume.KeystorePasswordFile)
	}
	o.Volume.KeystorePassword = password
	return nil
}
