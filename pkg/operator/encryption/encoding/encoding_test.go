package encoding

import (
	"encoding/json"
	"reflect"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestKMSPluginConfigRoundTrip(t *testing.T) {
	config := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": "kms.openshift.io/v1alpha1",
		"kind":       "VaultKMSConfig",
		"spec": map[string]interface{}{
			"vaultAddress": "https://vault.example.com",
			"vaultKeyPath": "transit/keys/key",
			"futureField":  "retained",
		},
		"status": map[string]interface{}{"kmsPluginImage": "quay.io/test/plugin:v1"},
	}}
	data, err := EncodeKMSPluginConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]interface{}
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(object, config.Object) {
		t.Fatalf("encoded object differs from snapshot: %s", data)
	}
	decoded, err := DecodeKMSPluginConfig(data)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, config) {
		t.Fatalf("round trip changed configuration: %#v", decoded.Object)
	}
	if err := unstructured.SetNestedField(decoded.Object, "changed", "spec", "vaultAddress"); err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(decoded, config) {
		t.Fatal("decoded config aliases input")
	}
}

func TestKMSPluginConfigEncodingErrors(t *testing.T) {
	if _, err := EncodeKMSPluginConfig(nil); err == nil {
		t.Fatal("expected nil configuration error")
	}
	for _, data := range []string{"", "{", "[]"} {
		t.Run(data, func(t *testing.T) {
			if _, err := DecodeKMSPluginConfig([]byte(data)); err == nil {
				t.Fatal("expected malformed configuration error")
			}
		})
	}
}
