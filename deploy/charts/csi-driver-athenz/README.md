# csi-driver-athenz

<!-- AUTO-GENERATED -->

#### **image.repository** ~ `object`
> Default value:
> ```yaml
> approver: docker.io/athenz/athenz-csi-driver-approver
> driver: docker.io/athenz/athenz-csi-driver
> ```

Target image registry. This value is prepended to the target image repository, if set.  
For example:

```yaml
registry: docker.io
repository:
  driver: athenz/athenz-csi-driver
  approver: athenz/athenz-csi-driver-approver
```


```yaml
registry: docker.io
```
#### **image.tag** ~ `string`

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **image.digest** ~ `object`
> Default value:
> ```yaml
> {}
> ```
#### **image.digest.driver** ~ `string`

Target csi-driver driver digest. Override any tag, if set.  
For example:

```yaml
driver: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

#### **image.digest.approver** ~ `string`

Target csi-driver approver digest. Override any tag, if set.  
For example:

```yaml
approver: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

#### **image.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

-- Kubernetes imagePullPolicy on DaemonSet.
#### **imagePullSecrets** ~ `array`
> Default value:
> ```yaml
> []
> ```

-- Optional secrets used for pulling the csi-driver-athenz and csi-driver-athenz-approver container images
#### **app.logLevel** ~ `number`
> Default value:
> ```yaml
> 1
> ```

-- Verbosity of cert-manager-csi-driver logging.
#### **app.certificateRequestDuration** ~ `string`
> Default value:
> ```yaml
> 1h
> ```

-- Duration requested for requested certificates.
#### **app.extraCertificateRequestAnnotations** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

List of annotations to add to certificate requests  
  
For example:

```yaml
extraCertificateRequestAnnotations: app=csi-driver-athenz,foo=bar
```
#### **app.trustDomain** ~ `string`
> Default value:
> ```yaml
> cluster.local
> ```

-- The Trust Domain for this driver.
#### **app.name** ~ `string`
> Default value:
> ```yaml
> csi.cert-manager.athenz.io
> ```

-- The name for the CSI driver installation.
#### **app.issuer.name** ~ `string`
> Default value:
> ```yaml
> athenz-ca
> ```

-- Issuer name which is used to serve this Trust Domain.
#### **app.issuer.kind** ~ `string`
> Default value:
> ```yaml
> ClusterIssuer
> ```

-- Issuer kind which is used to serve this Trust Domain.
#### **app.issuer.group** ~ `string`
> Default value:
> ```yaml
> cert-manager.io
> ```

-- Issuer group which is used to serve this Trust Domain.
#### **app.driver.sourceCABundle** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Optional file containing a CA bundle that will be propagated to  
managed volumes.
#### **app.driver.volumeFileName.cert** ~ `string`
> Default value:
> ```yaml
> tls.crt
> ```

-- File name which signed certificates are written to in volumes.
#### **app.driver.volumeFileName.key** ~ `string`
> Default value:
> ```yaml
> tls.key
> ```

-- File name which private keys are written to in volumes.
#### **app.driver.volumeFileName.ca** ~ `string`
> Default value:
> ```yaml
> ca.crt
> ```

-- File name where the CA bundles are written to, if enabled.
#### **app.driver.volumeWriteMode** ~ `string`
> Default value:
> ```yaml
> in-place
> ```

-- Controls how certificate data is written into pod volumes.  
`in-place` (default) rewrites existing files so consumer inotify  
watches survive renewals. `atomic-dir` restores the upstream csi-lib timestamped-directory writer as a rollback path, and silently breaks raw-inotify consumers such as istio-agent on every renewal.
#### **app.driver.keystore.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

-- Master switch for PKCS12 / JKS keystore provisioning.
#### **app.driver.keystore.pkcs12FileName** ~ `string`
> Default value:
> ```yaml
> service.pkcs12
> ```

-- File name of the PKCS12 keystore written into the pod's volume.  
Set to an empty string to skip PKCS12 generation while still writing the JKS keystore. The keystore uses the legacy PKCS12 encoding to mirror `openssl pkcs12 -export -noiter -nomaciter` so old Java JREs remain compatible.
#### **app.driver.keystore.jksFileName** ~ `string`
> Default value:
> ```yaml
> service.jks
> ```

-- File name of the JKS keystore written into the pod's volume. Set  
to an empty string to skip JKS generation while still writing the  
PKCS12 keystore.
#### **app.driver.keystore.passwordFile** ~ `string`
> Default value:
> ```yaml
> ""
> ```

-- File path inside the driver container whose contents are read as  
the keystore password. Typically the mount path of a Secret-backed volume. When empty, the well-known Java default `changeit` is used. The password may also be supplied via the `KEYSTORE_PASSWORD` environment variable, which takes precedence over this file. The password is never accepted on the command line, to avoid leaking it via `ps`.
#### **app.driver.keystore.alias** ~ `string`
> Default value:
> ```yaml
> service
> ```

-- Alias used for the private key entry inside the JKS keystore.
#### **app.driver.volumes** ~ `array`
> Default value:
> ```yaml
> []
> ```

-- Optional extra volumes. Useful for mounting root CAs
#### **app.driver.volumeMounts** ~ `array`
> Default value:
> ```yaml
> []
> ```

- name: root-cas

```yaml
secret:
  secretName: root-ca-bundle
```

-- Optional extra volume mounts. Useful for mounting root CAs
#### **app.driver.csiDataDir** ~ `string`
> Default value:
> ```yaml
> /tmp/csi-driver-athenz
> ```

-- Configures the hostPath directory that the driver will write and mount volumes from.
#### **app.driver.resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```
#### **app.driver.nodeDriverRegistrarImage.registry** ~ `string`

Target image registry. This value is prepended to the target image repository, if set.  
For example:

```yaml
registry: registry.k8s.io
repository: sig-storage/csi-node-driver-registrar
```

#### **app.driver.nodeDriverRegistrarImage.repository** ~ `string`
> Default value:
> ```yaml
> registry.k8s.io/sig-storage/csi-node-driver-registrar
> ```

-- Target image repository.
#### **app.driver.nodeDriverRegistrarImage.tag** ~ `string`
> Default value:
> ```yaml
> v2.11.1
> ```

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **app.driver.nodeDriverRegistrarImage.digest** ~ `string`

Target image digest. Override any tag, if set.  
For example:

```yaml
digest: sha256:0e072dddd1f7f8fc8909a2ca6f65e76c5f0d2fcfb8be47935ae3457e8bbceb20
```

#### **app.driver.nodeDriverRegistrarImage.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

Kubernetes imagePullPolicy on node-driver.
#### **app.driver.livenessProbeImage.registry** ~ `string`

Target image registry. This value is prepended to the target image repository, if set.  
For example:

```yaml
registry: registry.k8s.io
repository: sig-storage/livenessprobe
```

#### **app.driver.livenessProbeImage.repository** ~ `string`
> Default value:
> ```yaml
> registry.k8s.io/sig-storage/livenessprobe
> ```

-- Target image repository.
#### **app.driver.livenessProbeImage.tag** ~ `string`
> Default value:
> ```yaml
> v2.12.0
> ```

Override the image tag to deploy by setting this variable. If no value is set, the chart's appVersion is used.

#### **app.driver.livenessProbeImage.pullPolicy** ~ `string`
> Default value:
> ```yaml
> IfNotPresent
> ```

-- Kubernetes imagePullPolicy on liveness probe.
#### **app.driver.livenessProbe.port** ~ `number`
> Default value:
> ```yaml
> 9809
> ```

-- The port that will expose the liveness of the csi-driver
#### **app.athenz.zts** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Athenz ZTS endpoint
#### **app.athenz.providerPrefix** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Provider prefix for the backend provider in ZTS which is responsible for verifying and issuing the identity.
#### **app.athenz.caCertFile** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Optional ZTS CA bundle
#### **app.athenz.dnsDomains** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- dns domains used to construct the Athenz service FQDN. Multiple domains can be specified separated by comma
#### **app.athenz.certCountryName** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Country name in the certificate
#### **app.athenz.certOrgName** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Organization name in the certificate
#### **app.athenz.cloudProvider** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Cloud provider name where the driver is running
#### **app.athenz.cloudRegion** ~ `unknown`
> Default value:
> ```yaml
> null
> ```

-- Cloud region where the driver is running
#### **app.approver.multiTenant** ~ `bool`
> Default value:
> ```yaml
> false
> ```
#### **app.approver.replicaCount** ~ `number`
> Default value:
> ```yaml
> 1
> ```

-- Number of replicas of the approver to run.
#### **app.approver.signerName** ~ `string`
> Default value:
> ```yaml
> clusterissuers.cert-manager.io/*
> ```

-- The signer name that csi-driver-athenz approver will be given  
permission to approve and deny. CertificateRequests referencing this signer name can be processed by the Athenz approver. See: https://cert-manager.io/docs/concepts/certificaterequest/#approval
#### **app.approver.readinessProbe.port** ~ `number`
> Default value:
> ```yaml
> 6060
> ```

-- Container port to expose csi-driver-athenz-approver HTTP readiness  
probe on default network interface.
#### **app.approver.metrics.port** ~ `number`
> Default value:
> ```yaml
> 9402
> ```

-- Port for exposing Prometheus metrics on 0.0.0.0 on path '/metrics'.
#### **app.approver.metrics.service.enabled** ~ `bool`
> Default value:
> ```yaml
> true
> ```

-- Create a Service resource to expose metrics endpoint.
#### **app.approver.metrics.service.type** ~ `string`
> Default value:
> ```yaml
> ClusterIP
> ```

-- Service type to expose metrics.
#### **app.approver.metrics.service.servicemonitor.enabled** ~ `bool`
> Default value:
> ```yaml
> false
> ```

Create Prometheus ServiceMonitor resource for csi-driver-athenz approver.
#### **app.approver.metrics.service.servicemonitor.prometheusInstance** ~ `string`
> Default value:
> ```yaml
> default
> ```

The value for the "prometheus" label on the ServiceMonitor. This allows for multiple Prometheus instances selecting difference ServiceMonitors using label selectors.
#### **app.approver.metrics.service.servicemonitor.interval** ~ `string`
> Default value:
> ```yaml
> 10s
> ```

The interval that the Prometheus will scrape for metrics.
#### **app.approver.metrics.service.servicemonitor.scrapeTimeout** ~ `string`
> Default value:
> ```yaml
> 5s
> ```

The timeout on each metric probe request.
#### **app.approver.metrics.service.servicemonitor.labels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Additional labels to give the ServiceMonitor resource.
#### **app.approver.resources** ~ `object`
> Default value:
> ```yaml
> {}
> ```
#### **priorityClassName** ~ `string`
> Default value:
> ```yaml
> ""
> ```

-- Optional priority class to be used for the csi-driver pods.
#### **commonLabels** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Labels to apply to all resources
#### **nodeSelector** ~ `object`
> Default value:
> ```yaml
> kubernetes.io/os: linux
> ```

Kubernetes node selector: node labels for pod assignment.

#### **affinity** ~ `object`
> Default value:
> ```yaml
> {}
> ```

Kubernetes affinity: constraints for pod assignment.  
  
For example:

```yaml
affinity:
  nodeAffinity:
   requiredDuringSchedulingIgnoredDuringExecution:
     nodeSelectorTerms:
     - matchExpressions:
       - key: foo.bar.com/role
         operator: In
         values:
         - master
```
#### **tolerations** ~ `array`
> Default value:
> ```yaml
> []
> ```

Kubernetes pod tolerations for cert-manager-csi-driver-spiffe.  
  
For example:

```yaml
tolerations:
- key: foo.bar.com/role
  operator: Equal
  value: master
  effect: NoSchedule
```
#### **topologySpreadConstraints** ~ `array`
> Default value:
> ```yaml
> []
> ```

List of Kubernetes TopologySpreadConstraints.  
  
For example:

```yaml
topologySpreadConstraints:
- maxSkew: 2
  topologyKey: topology.kubernetes.io/zone
  whenUnsatisfiable: ScheduleAnyway
  labelSelector:
    matchLabels:
      app.kubernetes.io/instance: cert-manager
      app.kubernetes.io/component: controller
```

