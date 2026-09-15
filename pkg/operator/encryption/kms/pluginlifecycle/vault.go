package pluginlifecycle

import (
	"fmt"

	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/utils/ptr"
)

// newVaultSidecarProvider creates a Vault sidecar provider from the given KMS plugin data.
// It assumes the input data has been already been validated.
func newVaultSidecarProvider(name, keyID, udsPath string, vaultConfig *unstructured.Unstructured, refData *referenceDataResolver) (*vault, error) {
	secretName, err := kms.PluginConfigSpecString(vaultConfig, "authentication", "appRole", "secret", "name")
	if err != nil {
		return nil, err
	}
	if secretName == "" {
		return nil, fmt.Errorf("vault AppRole authentication secret name cannot be empty")
	}

	roleID, err := refData.SecretValue(secretName, "role-id")
	if err != nil {
		return nil, err
	}

	if roleID == "" {
		return nil, fmt.Errorf("role ID cannot be empty")
	}

	secretIDPath, err := refData.SecretFilePath(secretName, "secret-id")
	if err != nil {
		return nil, err
	}

	if secretIDPath == "" {
		return nil, fmt.Errorf("secret ID path cannot be empty")
	}

	var caBundlePath string
	configMapName, err := kms.PluginConfigSpecString(vaultConfig, "tls", "caBundle", "name")
	if err != nil {
		return nil, err
	}
	if configMapName != "" {
		caBundlePath, err = refData.ConfigMapFilePath(configMapName, "ca-bundle.crt")
		if err != nil {
			return nil, err
		}
	}

	return &vault{
		name:         name,
		keyID:        keyID,
		udsPath:      udsPath,
		config:       vaultConfig.DeepCopy(),
		roleID:       roleID,
		secretIDPath: secretIDPath,
		caBundlePath: caBundlePath,
	}, nil
}

// vault implements SidecarProvider for HashiCorp Vault KMS.
type vault struct {
	name         string
	keyID        string
	udsPath      string
	config       *unstructured.Unstructured
	roleID       string
	secretIDPath string
	caBundlePath string
}

// Name returns the sidecar name appended by the key id.
func (v *vault) Name() string {
	return fmt.Sprintf("%s-%s", v.name, v.keyID)
}

// BuildSidecarContainer returns a container spec for the Vault KMS plugin sidecar
// configured with the Vault address, namespace, transit mount, and transit key.
func (v *vault) BuildSidecarContainer() (corev1.Container, error) {
	image, err := kms.PluginConfigStatusString(v.config, "kmsPluginImage")
	if err != nil {
		return corev1.Container{}, err
	}

	address, err := kms.PluginConfigSpecString(v.config, "vaultAddress")
	if err != nil {
		return corev1.Container{}, err
	}

	keyPath, err := kms.PluginConfigSpecString(v.config, "vaultKeyPath")
	if err != nil {
		return corev1.Container{}, err
	}

	namespace, err := kms.PluginConfigSpecString(v.config, "vaultNamespace")
	if err != nil {
		return corev1.Container{}, err
	}

	authNamespace, err := kms.PluginConfigSpecString(v.config, "vaultAuthNamespace")
	if err != nil {
		return corev1.Container{}, err
	}

	serverName, err := kms.PluginConfigSpecString(v.config, "tls", "serverName")
	if err != nil {
		return corev1.Container{}, err
	}

	// Required API fields: always set.
	args := []string{
		fmt.Sprintf("-listen-address=%s", v.udsPath),
		fmt.Sprintf("-vault-address=%s", address),
		fmt.Sprintf("-vault-key-path=%s", keyPath),
		fmt.Sprintf("-approle-role-id=%s", v.roleID),
		fmt.Sprintf("-approle-secret-id-path=%s", v.secretIDPath),
	}

	// Optional fields: only pass non-empty values.
	if v.caBundlePath != "" {
		args = append(args, fmt.Sprintf("-tls-ca-file=%s", v.caBundlePath))
	}
	if serverName != "" {
		args = append(args, fmt.Sprintf("-tls-sni=%s", serverName))
	}
	if namespace != "" {
		args = append(args, fmt.Sprintf("-vault-namespace=%s", namespace))
	}
	if authNamespace != "" {
		args = append(args, fmt.Sprintf("-vault-auth-namespace=%s", authNamespace))
	}

	// Temporary workarounds. These should go away as we progress with the feature.
	args = append(args,
		// TODO: remove once we support scraping metrics from each KMS plugin sidecar independently.
		// Set the port to zero to disable metrics serving.
		// Slack discussion: https://redhat-external.slack.com/archives/C09KZ5QCBUH/p1780926464635219
		"-metrics-port=0",
	)

	return corev1.Container{
		Name:            v.Name(),
		Image:           image,
		Args:            args,
		ImagePullPolicy: corev1.PullIfNotPresent,
		// We place the container in InitContainers with RestartPolicyAlways so the kubelet starts it before
		// regular containers and keeps it running for the pod's lifetime.
		RestartPolicy:            ptr.To(corev1.ContainerRestartPolicyAlways),
		TerminationMessagePolicy: corev1.TerminationMessageFallbackToLogsOnError,
		// Vault team recommendation based on single-node OCP cluster measurements:
		// ~10 mCPU / 32-64 MiB steady state, memory peaked at ~60 MiB under 400 KEK rotations.
		// Slack discussion: https://redhat-external.slack.com/archives/C09KZ5QCBUH/p1779134070543079
		Resources: corev1.ResourceRequirements{
			Requests: corev1.ResourceList{
				corev1.ResourceMemory: resource.MustParse("64Mi"),
				corev1.ResourceCPU:    resource.MustParse("10m"),
			},
		},
		SecurityContext: &corev1.SecurityContext{
			ReadOnlyRootFilesystem:   ptr.To(true),
			AllowPrivilegeEscalation: ptr.To(false),
			Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			SeccompProfile:           &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
	}, nil
}
