package controllers

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	"github.com/openshift/library-go/pkg/operator/encryption/kms"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

// ResolveKMSConfig fetches a cluster-scoped plugin configuration through its API
// resource reference, validates required fields, and returns the object unchanged.
func ResolveKMSConfig(ctx context.Context, client dynamic.Interface, reference configv1.KMSPluginConfig) (*unstructured.Unstructured, error) {
	if client == nil {
		return nil, fmt.Errorf("dynamic client is required to resolve KMS plugin configuration")
	}
	ref := reference.PluginConfig
	gv, err := schema.ParseGroupVersion(ref.APIVersion)
	if err != nil {
		return nil, fmt.Errorf("invalid KMS plugin configuration apiVersion %q: %w", ref.APIVersion, err)
	}
	obj, err := client.Resource(gv.WithResource(ref.Resource)).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get KMS plugin configuration %s %s/%s: %w", ref.APIVersion, ref.Resource, ref.Name, err)
	}
	if obj == nil || len(obj.Object) == 0 {
		return nil, fmt.Errorf("KMS plugin configuration must not be nil or empty")
	}
	image, err := kms.PluginConfigStatusString(obj, "kmsPluginImage")
	if err != nil {
		return nil, err
	}
	if image == "" {
		return nil, fmt.Errorf("KMS plugin configuration status.kmsPluginImage must not be empty")
	}
	if reference.Type == configv1.VaultKMSProvider {
		paths := [][]string{{"vaultAddress"}, {"vaultKeyPath"}, {"authentication", "type"}}
		authType, err := kms.PluginConfigSpecString(obj, "authentication", "type")
		if err != nil {
			return nil, err
		}
		if authType == string(configv1.VaultAuthenticationTypeAppRole) {
			paths = append(paths, []string{"authentication", "appRole", "secret", "name"})
		}
		_, hasCABundle, err := unstructured.NestedFieldNoCopy(obj.Object, "spec", "tls", "caBundle")
		if err != nil {
			return nil, err
		}
		if hasCABundle {
			paths = append(paths, []string{"tls", "caBundle", "name"})
		}
		for _, path := range paths {
			value, err := kms.PluginConfigSpecString(obj, path...)
			if err != nil {
				return nil, err
			}
			if value == "" {
				return nil, fmt.Errorf("KMS plugin configuration spec.%s must not be empty", strings.Join(path, "."))
			}
		}
	}
	return obj, nil
}
