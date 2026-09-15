package kms

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestPluginConfigStrings(t *testing.T) {
	for _, accessor := range []struct {
		section string
		read    func(*unstructured.Unstructured, ...string) (string, error)
	}{
		{section: "spec", read: PluginConfigSpecString},
		{section: "status", read: PluginConfigStatusString},
	} {
		t.Run(accessor.section, func(t *testing.T) {
			for _, tc := range []struct {
				name    string
				object  map[string]interface{}
				want    string
				wantErr bool
			}{
				{name: "missing", object: map[string]interface{}{}},
				{name: "empty", object: map[string]interface{}{accessor.section: map[string]interface{}{"field": ""}}},
				{name: "value", object: map[string]interface{}{accessor.section: map[string]interface{}{"field": "value"}}, want: "value"},
				{name: "section isolation", object: map[string]interface{}{"field": "root", "spec": map[string]interface{}{"field": "spec"}, "status": map[string]interface{}{"field": "status"}}, want: accessor.section},
				{name: "wrong leaf type", object: map[string]interface{}{accessor.section: map[string]interface{}{"field": int64(1)}}, wantErr: true},
				{name: "wrong parent type", object: map[string]interface{}{accessor.section: "invalid"}, wantErr: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					got, err := accessor.read(&unstructured.Unstructured{Object: tc.object}, "field")
					if (err != nil) != tc.wantErr || got != tc.want {
						t.Fatalf("got (%q,%v), expected (%q,error=%v)", got, err, tc.want, tc.wantErr)
					}
					if err != nil && !strings.Contains(err.Error(), accessor.section+".field") {
						t.Fatalf("error does not identify field path: %v", err)
					}
				})
			}
			if _, err := accessor.read(nil, "field"); err == nil {
				t.Fatal("expected nil configuration error")
			}
			config := &unstructured.Unstructured{Object: map[string]interface{}{accessor.section: map[string]interface{}{"nested": map[string]interface{}{"field": "value"}}}}
			if got, err := accessor.read(config, "nested", "field"); err != nil || got != "value" {
				t.Fatalf("nested field: got (%q,%v)", got, err)
			}
		})
	}
}
