package controllers

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	configv1clientfake "github.com/openshift/client-go/config/clientset/versioned/fake"
	"github.com/openshift/library-go/pkg/operator/encryption/encryptiondata"
	"github.com/openshift/library-go/pkg/operator/encryption/state"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestResolveKMSConfig(t *testing.T) {
	ctx := context.Background()
	obj := vaultPluginConfig(t, wellKnownBaseVaultConfig)
	obj.SetName("selected")
	obj.SetResourceVersion("42")
	obj.SetAnnotations(map[string]string{"unrelated": "value"})
	require.NoError(t, unstructured.SetNestedField(obj.Object, "quay.io/test/plugin:v1", "status", "kmsPluginImage"))
	require.NoError(t, unstructured.SetNestedField(obj.Object, "ignored", "status", "unrelated"))
	reference := kmsPluginConfigReference()
	reference.PluginConfig.Name = obj.GetName()
	client := newKMSDynamicClient(t, obj)

	resolved, err := ResolveKMSConfig(ctx, client, reference)
	require.NoError(t, err)
	require.Len(t, client.Actions(), 1)
	action := client.Actions()[0].(k8stesting.GetAction)
	require.Equal(t, schema.GroupVersionResource{Group: "kms.openshift.io", Version: "v1alpha1", Resource: "vaultkmsconfigs"}, action.GetResource())
	require.Equal(t, "selected", action.GetName())
	require.Empty(t, action.GetNamespace())
	require.Equal(t, obj.GetResourceVersion(), resolved.GetResourceVersion())
	require.Equal(t, obj.GetAnnotations(), resolved.GetAnnotations())
	require.Equal(t, obj.Object["status"], resolved.Object["status"])
	require.Equal(t, obj.Object["spec"], resolved.Object["spec"])

	require.NoError(t, unstructured.SetNestedField(resolved.Object, "changed", "spec", "vaultAddress"))
	stored, err := client.Resource(action.GetResource()).Get(ctx, "selected", metav1.GetOptions{})
	require.NoError(t, err)
	address, _, err := unstructured.NestedString(stored.Object, "spec", "vaultAddress")
	require.NoError(t, err)
	require.Equal(t, "https://vault.example.com:8200", address)
}

func TestResolveKMSConfigErrors(t *testing.T) {
	ctx := context.Background()
	reference := kmsPluginConfigReference()
	t.Run("missing dynamic client", func(t *testing.T) {
		_, err := ResolveKMSConfig(ctx, nil, reference)
		require.ErrorContains(t, err, "dynamic client is required")
	})
	t.Run("invalid apiVersion", func(t *testing.T) {
		invalid := reference
		invalid.PluginConfig.APIVersion = "group/version/extra"
		client := newKMSDynamicClient(t)
		_, err := ResolveKMSConfig(ctx, client, invalid)
		require.ErrorContains(t, err, "apiVersion")
		require.Empty(t, client.Actions())
	})
	t.Run("not found", func(t *testing.T) {
		missing := reference
		missing.PluginConfig.Name = "missing"
		_, err := ResolveKMSConfig(ctx, newKMSDynamicClient(t), missing)
		require.True(t, apierrors.IsNotFound(err), "%v", err)
		require.ErrorContains(t, err, "vaultkmsconfigs/missing")
	})
	t.Run("forbidden", func(t *testing.T) {
		client := newKMSDynamicClient(t)
		client.PrependReactor("get", "vaultkmsconfigs", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, apierrors.NewForbidden(schema.GroupResource{Group: "kms.openshift.io", Resource: "vaultkmsconfigs"}, "cluster", fmt.Errorf("denied"))
		})
		_, err := ResolveKMSConfig(ctx, client, reference)
		require.True(t, apierrors.IsForbidden(err), "%v", err)
	})

}

func TestPreflightUsesFetchedPluginConfig(t *testing.T) {
	ctx := context.Background()
	client := newKMSDynamicClient(t)
	resolved, err := ResolveKMSConfig(ctx, client, kmsPluginConfigReference())
	require.NoError(t, err)
	changed := vaultPluginConfig(t, wellKnownBaseVaultConfig)
	changed.SetName("cluster")
	require.NoError(t, unstructured.SetNestedField(changed.Object, "transit/keys/changed", "spec", "vaultKeyPath"))
	_, err = client.Resource(schema.GroupVersionResource{Group: "kms.openshift.io", Version: "v1alpha1", Resource: "vaultkmsconfigs"}).Update(ctx, changed, metav1.UpdateOptions{})
	require.NoError(t, err)
	client.ClearActions()
	client.PrependReactor("get", "*", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, fmt.Errorf("must not refetch resolved plugin config")
	})
	computer := newKMSPreflightComputeComputer(t, []runtime.Object{&wellKnownBaseSecret, &wellKnownBaseConfigMap}, &fakeEncryptionDeployer{converged: true}, newKMSVaultAPIServer(), newTestProvider([]schema.GroupResource{{Resource: "secrets"}}), "test").(*encryptionConfigurationComputer)
	computer.dynamicClient = client
	// No APIServer object: the prefetched reference must also be reused.
	computer.apiServerClient = configv1clientfake.NewSimpleClientset().ConfigV1().APIServers()
	reference := kmsPluginConfigReference()
	secret, err := computer.ComputeEncryptionConfiguration(ctx, &reference, resolved)
	require.NoError(t, err)
	config, err := encryptiondata.FromSecret(secret)
	require.NoError(t, err)
	require.Equal(t, resolved, config.KMSPlugins["1"])
	require.Empty(t, client.Actions())
}

func TestResolveKMSConfigNilObject(t *testing.T) {
	for _, obj := range []*unstructured.Unstructured{nil, {}} {
		client := newKMSDynamicClient(t)
		client.PrependReactor("get", "vaultkmsconfigs", func(k8stesting.Action) (bool, runtime.Object, error) {
			if obj == nil {
				return true, nil, nil
			}
			return true, obj, nil
		})
		config, err := ResolveKMSConfig(context.Background(), client, kmsPluginConfigReference())
		require.Nil(t, config)
		require.Error(t, err)
	}
}

func TestKMSProviderNilObject(t *testing.T) {
	for _, obj := range []*unstructured.Unstructured{nil, {}} {
		_, err := newKMSProviderConfig(configv1.VaultKMSProvider, obj)
		require.Error(t, err)
		_, _, _, err = buildEncryptionKeyState(context.Background(), 1, state.KMS, obj, nil, nil, nil, "", "")
		require.Error(t, err)
	}
}

func TestKMSHashConfigurationSelection(t *testing.T) {
	hashConfig := func(obj *unstructured.Unstructured) string {
		t.Helper()
		provider, err := newKMSProviderConfig(configv1.VaultKMSProvider, obj)
		require.NoError(t, err)
		client := fake.NewSimpleClientset(&wellKnownBaseSecret, &wellKnownBaseConfigMap).CoreV1()
		hasher, err := newKMSConfigHasher(provider, newCoreClientKMSConfigHasherResourceProvider(client, client), "openshift-config")
		require.NoError(t, err)
		hash, err := hasher.hash(context.Background())
		require.NoError(t, err)
		return hash
	}
	base := wellKnownBaseVaultConfig.DeepCopy()
	base.SetName("cluster")
	baselineHash := hashConfig(base)
	for _, tc := range []struct {
		name        string
		path        []string
		value       interface{}
		changesHash bool
	}{
		{name: "resource version", path: []string{"metadata", "resourceVersion"}, value: "42"},
		{name: "annotations", path: []string{"metadata", "annotations", "note"}, value: "changed"},
		{name: "unrelated status", path: []string{"status", "conditions"}, value: []interface{}{map[string]interface{}{"type": "Ready", "status": "True"}}},
		{name: "spec field", path: []string{"spec", "vaultAddress"}, value: "https://changed.example.com", changesHash: true},
		{name: "unknown spec field", path: []string{"spec", "futureSetting"}, value: "changed", changesHash: true},
		{name: "image", path: []string{"status", "kmsPluginImage"}, value: "quay.io/test/plugin:v2", changesHash: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base.DeepCopy()
			require.NoError(t, unstructured.SetNestedField(changed.Object, tc.value, tc.path...))
			before := changed.DeepCopy()
			result := hashConfig(changed)
			if tc.changesHash {
				require.NotEqual(t, baselineHash, result)
			} else {
				require.Equal(t, baselineHash, result)
			}
			require.Equal(t, before, changed)
		})
	}
	t.Run("map insertion order", func(t *testing.T) {
		changed := base.DeepCopy()
		spec := changed.Object["spec"].(map[string]interface{})
		keys := make([]string, 0, len(spec))
		for key := range spec {
			keys = append(keys, key)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		reversed := map[string]interface{}{}
		for _, key := range keys {
			reversed[key] = spec[key]
		}
		changed.Object["spec"] = reversed
		require.Equal(t, baselineHash, hashConfig(changed))
	})
	t.Run("hash input does not alias the CR", func(t *testing.T) {
		provider, err := newKMSProviderConfig(configv1.VaultKMSProvider, base)
		require.NoError(t, err)
		before := base.DeepCopy()
		input := provider.sourceConfig().(*unstructured.Unstructured)
		require.Len(t, input.Object, 2)
		require.Contains(t, input.Object, "spec")
		require.Equal(t, map[string]interface{}{"kmsPluginImage": ""}, input.Object["status"])
		require.NoError(t, unstructured.SetNestedField(input.Object, "changed", "spec", "vaultAddress"))
		require.Equal(t, before, base)
	})
}

func TestKMSProviderMalformedHashFields(t *testing.T) {
	for _, path := range [][]string{{"spec"}, {"status"}, {"status", "kmsPluginImage"}} {
		t.Run(strings.Join(path, "."), func(t *testing.T) {
			obj := wellKnownBaseVaultConfig.DeepCopy()
			require.NoError(t, unstructured.SetNestedField(obj.Object, int64(1), path...))
			_, err := newKMSProviderConfig(configv1.VaultKMSProvider, obj)
			require.ErrorContains(t, err, strings.Join(path, "."))
		})
	}
}
