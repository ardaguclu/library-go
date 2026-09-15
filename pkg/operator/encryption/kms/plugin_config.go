package kms

import (
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// PluginConfigSpecString reads a string field from the plugin configuration spec.
// Missing fields retain their zero value; required-field validation belongs to resolution.
func PluginConfigSpecString(config *unstructured.Unstructured, fields ...string) (string, error) {
	return pluginConfigString(config, append([]string{"spec"}, fields...)...)
}

// PluginConfigStatusString reads a string field from the plugin configuration status.
// Missing fields retain their zero value; required-field validation belongs to resolution.
func PluginConfigStatusString(config *unstructured.Unstructured, fields ...string) (string, error) {
	return pluginConfigString(config, append([]string{"status"}, fields...)...)
}

func pluginConfigString(config *unstructured.Unstructured, fields ...string) (string, error) {
	if config == nil {
		return "", fmt.Errorf("KMS plugin config cannot be nil")
	}
	value, _, err := unstructured.NestedString(config.Object, fields...)
	if err != nil {
		return "", fmt.Errorf("invalid KMS plugin config field %s: %w", strings.Join(fields, "."), err)
	}
	return value, nil
}
