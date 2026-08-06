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
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	cmclient "github.com/cert-manager/cert-manager/pkg/client/clientset/versioned"
	"github.com/cert-manager/csi-lib/driver"
	"github.com/cert-manager/csi-lib/manager"
	"github.com/cert-manager/csi-lib/manager/util"
	"github.com/cert-manager/csi-lib/metadata"
	"github.com/cert-manager/csi-lib/storage"
	"github.com/go-logr/logr"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"gopkg.in/square/go-jose.v2/jwt"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
	pkcs12 "software.sslmate.com/src/go-pkcs12"

	"github.com/AthenZ/csi-driver-athenz/internal/csi/rootca"
)

// DefaultKeystorePassword is the password used to encrypt the PKCS12 / JKS
// keystores when none is configured. Matches the conventional Java keystore
// default.
const DefaultKeystorePassword = "changeit"

// DefaultKeystoreAlias is the alias used for the private key entry inside the
// generated JKS keystore.
const DefaultKeystoreAlias = "service"

const (
	cloudMetaEndpoint      = "http://169.254.169.254:80"
	attrPodSubdomain       = "csi.cert-manager.athenz.io/pod-subdomain"
	attrPodHostname        = "csi.cert-manager.athenz.io/pod-hostname"
	attrPodService         = "csi.cert-manager.athenz.io/pod-service"
	attrNSForDomain        = "csi.cert-manager.athenz.io/use-namespace-for-domain"
	attrRefreshInterval    = "csi.cert-manager.athenz.io/refresh-interval"
	clusterZone            = "cluster.local"
	defaultRefreshInterval = 24 * time.Hour
)

// Options holds the Options needed for the CSI driver.
type Options struct {
	// DriverName is the driver name as installed in Kubernetes.
	DriverName string

	// NodeID is the name of the node the driver is running on.
	NodeID string

	// DataRoot is the path to the in-memory data directory used to store data.
	DataRoot string

	// Endpoint is the endpoint which is used to listen for gRPC requests.
	Endpoint string

	// TrustDomain is the trust domain of this Athenz PKI. The TrustDomain will
	// appear in signed certificate's URI SANs.
	TrustDomain string

	// CertificateRequestAnnotations are annotations that are to be added to certificate requests created by the driver
	CertificateRequestAnnotations map[string]string

	// CertificateRequestDuration is the duration CertificateRequests will be
	// requested with.
	// Defaults to 1 hour if empty.
	CertificateRequestDuration time.Duration

	// IssuerRef is the IssuerRef used when creating CertificateRequests.
	IssuerRef cmmeta.ObjectReference

	// CertificateFileName is the name of the file that the signed certificate
	// will be written to inside the Pod's volume.
	// Default to `tls.crt` if empty.
	CertificateFileName string

	// KeyFileName is the name of the file that the private key will be written
	// to inside the Pod's volume.
	// Default to `tls.key` if empty.
	KeyFileName string

	// CAFileName is the name of the file that the root CA certificates will be
	// written to inside the Pod's volume. Ignored if RootCAs is nil.
	CAFileName string

	// KeystoreEnabled is the master switch for PKCS12 / JKS keystore
	// provisioning. When false (the default), no keystores are written and
	// the keystore-related options below are ignored.
	KeystoreEnabled bool

	// KeystoreFileName is the name of the PKCS12 keystore file written into the
	// Pod's volume. The keystore contains the private key and leaf certificate,
	// using the legacy PKCS12 encoding. Has no effect unless KeystoreEnabled
	// is true. If empty when KeystoreEnabled is true, no PKCS12 keystore is
	// written.
	KeystoreFileName string

	// JKSFileName is the name of the JKS keystore file written into the Pod's
	// volume. The keystore contains the private key and leaf certificate. Has
	// no effect unless KeystoreEnabled is true. If empty when KeystoreEnabled
	// is true, no JKS keystore is written.
	JKSFileName string

	// KeystorePassword is the password used to encrypt both the PKCS12 and JKS
	// keystores. Defaults to DefaultKeystorePassword if empty.
	KeystorePassword string

	// KeystoreAlias is the alias used for the private key entry inside the
	// JKS keystore. Defaults to DefaultKeystoreAlias if empty.
	KeystoreAlias string

	// WriteMode selects how certificate data is written into the Pod's volume.
	// WriteModeAtomicDir (the default when empty) is the upstream csi-lib
	// timestamped-directory writer. WriteModeInPlace rewrites the existing
	// files instead, so their inodes - and therefore the inotify watches
	// consumers hold on them - survive a renewal.
	WriteMode string

	// RestConfig is used for interacting with the Kubernetes API server.
	RestConfig *rest.Config

	// RootCAs is optionally used to write root CA certificate data to Pod's
	// volume. If nil, no root CA data is written to Pod's volume. If defined,
	// root CA data will be written to the file with the name defined in
	// CAFileName. If the root CA certificate data changes, all managed volume's
	// file will be updated.
	RootCAs rootca.Interface

	// ZTS is the URL of the ZTS server
	ZTS string

	// Provider prefix for the backend provider in ZTS which is responsible
	// for verifying and issuing the identity.
	ProviderPrefix string

	// Trust store bundle is optionally used for the ZTS server if ZTS server certificate
	// is not signed by well known CA.
	CACertFile string

	// DNS domains to be added to the certificate
	DNSDomains string

	// Country name for the certificate
	CertCountryName string

	// Organization name for the certificate
	CertOrgName string

	// Cloud provider where service is running
	CloudProvider string

	// Cloud region where service is running
	CloudRegion string
}

// Driver is used for running the actual CSI driver. Driver will respond to
// NodePublishVolume events, and attempt to sign Athenz certificates for
// mounting pod's identity.
type Driver struct {
	// log is the Driver logger.
	log logr.Logger

	// trustDomain is the trust domain that will form pod identities.
	trustDomain string

	// certificateRequestDuration is the duration which will be set of all
	// created CertificateRequests.
	certificateRequestDuration time.Duration

	// issuerRef is the issuerRef that will be set on all created
	// CertificateRequests.
	issuerRef cmmeta.ObjectReference

	// certFileName, keyFileName, caFileName are the names used when writing file
	// to volumes.
	certFileName, keyFileName, caFileName string

	// keystoreEnabled gates PKCS12 / JKS provisioning entirely. When false,
	// keystoreFileName and jksFileName are ignored.
	keystoreEnabled bool

	// keystoreFileName is the file name of the PKCS12 keystore written to
	// volumes. Ignored when keystoreEnabled is false; if empty when enabled,
	// no PKCS12 keystore is written.
	keystoreFileName string

	// jksFileName is the file name of the JKS keystore written to volumes.
	// Ignored when keystoreEnabled is false; if empty when enabled, no JKS
	// keystore is written.
	jksFileName string

	// keystorePassword is the password used to encrypt the PKCS12 / JKS
	// keystores.
	keystorePassword string

	// keystoreAlias is the alias used for the private key entry inside the
	// JKS keystore.
	keystoreAlias string

	// rootCAs provides the root CA certificates to write to file. No CA file is
	// written if this is nil.
	rootCAs rootca.Interface

	// driver is the csi-lib implementation of a cert-manager CSI driver.
	driver *driver.Driver

	// store is the csi-lib implementation of a cert-manager CSI storage manager.
	store storage.Interface

	// camanager is used to update all managed volumes with the current root CA
	// certificates PEM.
	camanager *camanager

	// zts is the URL of the ZTS server
	zts string

	// prefix for the backend provider in ZTS which is responsible
	// for verifying and issuing the identity.
	providerPrefix string

	// Trust store bundle is optionally used for the ZTS server if ZTS server certificate
	// is not signed by well known CA.
	caCertFile string

	// DNS domains to be added to the certificate
	dnsDomains string

	// Country name for the certificate
	certCountryName string

	// Organization name for the certificate
	certOrgName string

	// Cloud provider where service is running
	cloudProvider string

	// Cloud region where service is running
	cloudRegion string
}

// New constructs a new Driver instance.
func New(ctx context.Context, log logr.Logger, opts Options) (*Driver, error) {
	d := &Driver{
		log:                        log.WithName("csi"),
		trustDomain:                opts.TrustDomain,
		certFileName:               opts.CertificateFileName,
		keyFileName:                opts.KeyFileName,
		caFileName:                 opts.CAFileName,
		keystoreEnabled:            opts.KeystoreEnabled,
		keystoreFileName:           opts.KeystoreFileName,
		jksFileName:                opts.JKSFileName,
		keystorePassword:           opts.KeystorePassword,
		keystoreAlias:              opts.KeystoreAlias,
		issuerRef:                  opts.IssuerRef,
		rootCAs:                    opts.RootCAs,
		certificateRequestDuration: opts.CertificateRequestDuration,
		zts:                        opts.ZTS,
		providerPrefix:             opts.ProviderPrefix,
		caCertFile:                 opts.CACertFile,
		dnsDomains:                 opts.DNSDomains,
		certCountryName:            opts.CertCountryName,
		certOrgName:                opts.CertOrgName,
		cloudProvider:              opts.CloudProvider,
		cloudRegion:                opts.CloudRegion,
	}

	// Set sane defaults.
	if len(d.certFileName) == 0 {
		d.certFileName = "tls.crt"
	}
	if len(d.keyFileName) == 0 {
		d.keyFileName = "tls.key"
	}
	if len(d.caFileName) == 0 {
		d.caFileName = "ca.crt"
	}
	if d.certificateRequestDuration == 0 {
		d.certificateRequestDuration = time.Hour
	}
	if d.keystoreEnabled && len(d.keystorePassword) == 0 {
		d.keystorePassword = DefaultKeystorePassword
	}
	if len(d.keystoreAlias) == 0 {
		d.keystoreAlias = DefaultKeystoreAlias
	}

	var err error
	store, err := storage.NewFilesystem(d.log, opts.DataRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to setup filesystem: %w", err)
	}
	// Used by clients to set the stored file's file-system group before
	// mounting. Must be set before the store is wrapped below, since the
	// in-place writer copies the key at construction.
	store.FSGroupVolumeAttributeKey = "csi.cert-manager.athenz.io/fs-group"

	// The CA manager writes to the same volumes as the driver, so it has to use
	// the same writer: if it kept the atomic writer it would recreate the
	// `..data` layout on a CA bundle update and break every live watch again.
	var caStore volumeStore
	switch opts.WriteMode {
	case WriteModeInPlace:
		inplace := newInplaceWriteStorage(store, d.certFileName)
		d.store = inplace
		caStore = inplace
	case "", WriteModeAtomicDir:
		atomicDir := newAtomicDirStorage(store)
		d.store = atomicDir
		caStore = atomicDir
	default:
		return nil, fmt.Errorf("invalid volume write mode %q, must be one of %q or %q",
			opts.WriteMode, WriteModeInPlace, WriteModeAtomicDir)
	}

	d.camanager = newCAManager(log, caStore, opts.RootCAs,
		d.certFileName, d.keyFileName, d.caFileName)

	cmclient, err := cmclient.NewForConfig(opts.RestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build cert-manager client: %w", err)
	}

	mngrLog := d.log.WithName("manager")
	d.driver, err = driver.New(ctx, opts.Endpoint, d.log.WithName("driver"), driver.Options{
		DriverName:    opts.DriverName,
		DriverVersion: "v0.1.0",
		NodeID:        opts.NodeID,
		Store:         d.store,
		Manager: manager.NewManagerOrDie(manager.Options{
			Client: cmclient,
			// Use Pod's service account to request CertificateRequests.
			ClientForMetadata:    util.ClientForMetadataTokenRequestEmptyAud(opts.RestConfig),
			MaxRequestsPerVolume: 1,
			MetadataReader:       d.store,
			Clock:                clock.RealClock{},
			Log:                  &mngrLog,
			NodeID:               opts.NodeID,
			GeneratePrivateKey:   generatePrivateKey,
			GenerateRequest:      d.generateRequest,
			SignRequest:          signRequest,
			WriteKeypair:         d.writeKeypair,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to setup csi driver: %w", err)
	}

	return d, nil
}

// Run is a blocking func that run the CSI driver.
func (d *Driver) Run(ctx context.Context) error {
	var wg sync.WaitGroup

	go func() {
		<-ctx.Done()
		d.driver.Stop()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		d.camanager.run(ctx, time.Second*5)
	}()

	wg.Add(1)
	var err error
	go func() {
		defer wg.Done()
		err = d.driver.Run()
	}()

	wg.Wait()
	return err
}

// generateRequest will generate a Athenz manager.CertificateRequestBundle
// based upon the identity contained in the metadata service account token.
func (d *Driver) generateRequest(meta metadata.Metadata) (*manager.CertificateRequestBundle, error) {
	// Extract the service account token from the volume metadata in order to
	// derive the service account, and thus identity of the pod.
	token, err := util.EmptyAudienceTokenFromMetadata(meta)
	if err != nil {
		return nil, err
	}

	jwttoken, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token request token: %w", err)
	}

	claims := struct {
		KubernetesIO struct {
			Namespace string `json:"namespace"`
			Pod       struct {
				Name string `json:"name"`
				Uid  string `json:"uid"`
			} `json:"pod"`
			ServiceAccount struct {
				Name string `json:"name"`
			} `json:"serviceaccount"`
		} `json:"kubernetes.io"`
	}{}

	// We don't need to verify the token since we will be using it against the
	// API server anyway which is the source of trust for auth by definition.
	if err := jwttoken.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, fmt.Errorf("failed to decode token request token: %w", err)
	}

	saName := claims.KubernetesIO.ServiceAccount.Name
	saNamespace := claims.KubernetesIO.Namespace
	podId := claims.KubernetesIO.Pod.Uid
	if len(saName) == 0 || len(saNamespace) == 0 {
		return nil, fmt.Errorf("missing namespace or serviceaccount name in request token: %v", claims)
	}

	spiffeID := fmt.Sprintf("spiffe://%s/ns/%s/sa/%s", d.trustDomain, saNamespace, saName)
	commonName := saName
	domain, service := extractDomainService(saName)

	useNSForDomain := meta.VolumeContext[attrNSForDomain]
	// if the non-standard service account annotation is set, then we will derive the athenz domain name from the
	// namespace name and the service account name
	if useNSForDomain == "true" {
		annotations, err := getNamespaceAnnotations(saNamespace)
		if err != nil {
			return nil, fmt.Errorf("failed to get domain namespace annotations: %w", err)
		}
		domain = getDomainFromNamespaceAnnotations(annotations)
		spiffeID = fmt.Sprintf("spiffe://%s/ns/%s/sa/%s.%s", d.trustDomain, saNamespace, domain, saName)
		commonName = fmt.Sprintf("%s.%s", domain, saName)
		service = saName
	}

	if domain == "" {
		return nil, fmt.Errorf("no domain found in either SA name OR in namespace annotations: %s", saNamespace)
	}

	spiffeUri, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("internal error crafting X.509 URI: %w", err)
	}

	subj := pkix.Name{CommonName: commonName}
	if d.certCountryName != "" {
		subj.Country = []string{d.certCountryName}
	}
	if d.certOrgName != "" {
		subj.Organization = []string{d.certOrgName}
	}

	hyphenDomain := strings.Replace(domain, ".", "-", -1)
	hostList := []string{}
	if len(d.dnsDomains) > 0 {
		dnsDomains := strings.Split(d.dnsDomains, ",")
		for _, dnsDomain := range dnsDomains {
			host := fmt.Sprintf("%s.%s.%s", service, hyphenDomain, dnsDomain)
			hostList = appendHostname(hostList, host)
			host = fmt.Sprintf("*.%s.%s.%s", service, hyphenDomain, dnsDomain)
			hostList = appendHostname(hostList, host)
		}
	}

	podSubdomain := meta.VolumeContext[attrPodSubdomain]
	podHostname := meta.VolumeContext[attrPodHostname]
	podService := meta.VolumeContext[attrPodService]

	if podService == "" {
		podService = service
	}

	if podHostname != "" {
		podSubdomainComp := ""
		if podSubdomain != "" {
			podSubdomainComp = "." + podSubdomain
		}
		hostList = append(hostList, fmt.Sprintf("%s%s.%s.svc.%s", podHostname, podSubdomainComp, saNamespace, clusterZone))
	}
	if podService != "" {
		hostList = append(hostList, fmt.Sprintf("%s.%s.svc.%s", podService, saNamespace, clusterZone))
		// K8S API server expects the san dns in this format if the certificate is to be used by a webhook
		hostList = append(hostList, fmt.Sprintf("%s.%s.svc", podService, saNamespace))
	}

	uris := []*url.URL{spiffeUri}

	providerName := fmt.Sprintf("%s.%s-%s", d.providerPrefix, d.cloudProvider, d.cloudRegion)
	instanceIdUri := fmt.Sprintf("athenz://instanceid/%s/%s", providerName, podId)
	uris = appendUri(uris, instanceIdUri)

	csr := &x509.CertificateRequest{
		DNSNames:           hostList,
		Subject:            subj,
		URIs:               uris,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	annotations := map[string]string{
		"csi.cert-manager.athenz.io/identity": spiffeID,
	}

	return &manager.CertificateRequestBundle{
		Request:   csr,
		IsCA:      false,
		Namespace: saNamespace,
		Duration:  d.certificateRequestDuration,
		Usages: []cmapi.KeyUsage{
			cmapi.UsageDigitalSignature,
			cmapi.UsageKeyEncipherment,
			cmapi.UsageServerAuth,
			cmapi.UsageClientAuth,
		},
		IssuerRef:   d.issuerRef,
		Annotations: annotations,
	}, nil
}

// writeKeypair writes the private key and certificate chain to file that will
// be mounted into the pod.
func (d *Driver) writeKeypair(meta metadata.Metadata, key crypto.PrivateKey, chain []byte, _ []byte) error {
	pemBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to marshal ECDSA private key for PEM encoding: %w", err)
	}

	keyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pemBytes,
		},
	)

	// Calculate the next issuance time before we write any data to file,
	// so if the write fails, we are not left in a bad state.
	// Parse refresh interval from volume context, defaults to 24h if not specified or invalid
	refreshIntervalStr := meta.VolumeContext[attrRefreshInterval]
	refreshInterval, err := parseRefreshInterval(refreshIntervalStr, defaultRefreshInterval)
	if err != nil {
		d.log.Error(err, "invalid refresh interval, using default", "default", defaultRefreshInterval.String())
	}
	nextIssuanceTime := calculateNextIssuanceTimeWithRefreshInterval(refreshInterval)
	d.log.Info("using refresh interval", "refreshInterval", refreshInterval.String(), "nextIssuanceTime", nextIssuanceTime.Format(time.RFC3339))

	data := map[string][]byte{
		d.certFileName: chain,
		d.keyFileName:  keyPEM,
	}
	// If configured, write the CA certificates as defined in RootCAs.
	if d.rootCAs != nil {
		data[d.caFileName] = d.rootCAs.CertificatesPEM()
	}

	if d.keystoreEnabled && (len(d.keystoreFileName) > 0 || len(d.jksFileName) > 0) {
		chainCerts, err := parseCertChain(chain)
		if err != nil {
			return fmt.Errorf("parsing certificate chain for keystore: %w", err)
		}
		leaf, fellBack := pickLeaf(chainCerts)
		if leaf == nil {
			return fmt.Errorf("no certificates found in chain for keystore")
		}
		if fellBack {
			d.log.Info("no non-CA certificate found in chain; falling back to the first cert for keystore",
				"chainLength", len(chainCerts),
				"leafSubject", leaf.Subject.String(),
				"leafIsCA", leaf.IsCA,
			)
		}

		if len(d.keystoreFileName) > 0 {
			p12, err := encodePKCS12(key, leaf, d.keystorePassword)
			if err != nil {
				return fmt.Errorf("failed to encode PKCS12 keystore: %w", err)
			}
			data[d.keystoreFileName] = p12
		}

		if len(d.jksFileName) > 0 {
			jks, err := encodeJKS(pemBytes, leaf, d.keystoreAlias, d.keystorePassword)
			if err != nil {
				return fmt.Errorf("failed to encode JKS keystore: %w", err)
			}
			data[d.jksFileName] = jks
		}
	}

	// Write data to the actual volume that gets mounted.
	if err := d.store.WriteFiles(meta, data); err != nil {
		return fmt.Errorf("writing data: %w", err)
	}

	meta.NextIssuanceTime = &nextIssuanceTime
	if err := d.store.WriteMetadata(meta.VolumeID, meta); err != nil {
		return fmt.Errorf("writing metadata: %w", err)
	}

	return nil
}

// encodePKCS12 builds a PKCS12 keystore containing the private key and leaf
// certificate, matching the legacy Athenz SIA behaviour produced by
// `openssl pkcs12 -export -noiter -nomaciter`. CA / intermediate certificates
// are intentionally omitted to mirror the legacy on-disk format.
func encodePKCS12(key crypto.PrivateKey, leaf *x509.Certificate, password string) ([]byte, error) {
	return pkcs12.LegacyRC2.Encode(key, leaf, nil, password)
}

// encodeJKS builds a JKS keystore containing the private key and leaf
// certificate, mirroring the legacy Athenz SIA behaviour produced by
// `keytool -importkeystore` from a PKCS12 source.
func encodeJKS(privateKeyDER []byte, leaf *x509.Certificate, alias, password string) ([]byte, error) {
	ks := keystore.New()
	if err := ks.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{
		// Use the leaf's NotBefore (not time.Now()) so the encoded JKS bytes
		// are a pure function of the certificate. This keeps the on-disk file
		// stable for a given cert and avoids needlessly tripping file
		// watchers when writeKeypair runs without the cert actually changing.
		CreationTime: leaf.NotBefore,
		PrivateKey:   privateKeyDER,
		CertificateChain: []keystore.Certificate{
			{Type: "X509", Content: leaf.Raw},
		},
	}, []byte(password)); err != nil {
		return nil, fmt.Errorf("setting JKS private key entry: %w", err)
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, []byte(password)); err != nil {
		return nil, fmt.Errorf("storing JKS keystore: %w", err)
	}
	return buf.Bytes(), nil
}

// pickLeaf returns the first non-CA certificate from certs (i.e. the end-entity
// leaf), regardless of position in the chain. As a safety net for chains where
// no certificate has IsCA=false (which would be unusual for an issued service
// identity), it falls back to the first certificate and reports fellBack=true
// so the caller can surface the anomaly. Returns (nil, false) if certs is
// empty.
func pickLeaf(certs []*x509.Certificate) (leaf *x509.Certificate, fellBack bool) {
	for _, c := range certs {
		if !c.IsCA {
			return c, false
		}
	}
	if len(certs) > 0 {
		return certs[0], true
	}
	return nil, false
}

// parseCertChain decodes all CERTIFICATE PEM blocks in data into x509
// certificates, preserving order.
func parseCertChain(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}
