package config

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/divinelabio/aegis/internal/sections"
)

func TestCommunityTrafficDocumentProjectsDurableRevisionForPaidRuntime(t *testing.T) {
	input := TrafficControlDocument{Revision: 7, Config: sections.SectionConfig{
		Enabled: true, ProtectionLevel: 3, Settings: map[string]interface{}{
			"geo":       map[string]interface{}{"enabled": false},
			"blacklist": map[string]interface{}{"enabled": true, "ips": []string{"192.0.2.7"}},
		},
	}}
	canonical, err := trafficControlRuntimeSectionConfig(input)
	if err != nil {
		t.Fatal(err)
	}
	control, ok := canonical.Settings["control"].(map[string]interface{})
	if !ok || control["revision"] != "pg-7" || len(control["checksum"].(string)) != 64 {
		t.Fatalf("missing durable runtime provenance: %+v", control)
	}
	if !canonical.Enabled || canonical.ProtectionLevel != 3 || !reflect.DeepEqual(canonical.Settings["geo"], input.Config.Settings["geo"]) || !reflect.DeepEqual(canonical.Settings["blacklist"], input.Config.Settings["blacklist"]) {
		t.Fatal("provenance migration changed an enforcement setting")
	}
	if _, changed := input.Config.Settings["control"]; changed {
		t.Fatal("projection mutated the persisted input")
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		t.Fatal(err)
	}
	var restarted sections.SectionConfig
	if err := json.Unmarshal(encoded, &restarted); err != nil {
		t.Fatal(err)
	}
	projected, err := trafficControlRuntimeSectionConfig(TrafficControlDocument{Revision: 7, Config: restarted})
	if err != nil || !reflect.DeepEqual(projected.Settings["control"], restarted.Settings["control"]) {
		t.Fatalf("projection was not stable across restart: %+v %v", projected, err)
	}
}

func TestTrafficRuntimeProjectionPreservesCommercialMetadata(t *testing.T) {
	metadata := map[string]interface{}{"revision": "tc-existing", "checksum": "existing-policy-checksum", "schema_version": float64(1), "updated_by": "operator"}
	input := TrafficControlDocument{Revision: 9, Config: sections.SectionConfig{Enabled: false, Settings: map[string]interface{}{"control": metadata}}}
	projected, err := trafficControlRuntimeSectionConfig(input)
	if err != nil || projected.Enabled || !reflect.DeepEqual(projected.Settings["control"], metadata) {
		t.Fatalf("commercial revision or explicit disable was changed: %+v %v", projected, err)
	}
}

func TestTrafficRuntimeProjectionRequiresPersistedRevision(t *testing.T) {
	if _, err := trafficControlRuntimeSectionConfig(TrafficControlDocument{Config: sections.SectionConfig{Enabled: true}}); err == nil {
		t.Fatal("unpersisted policy was given runtime provenance")
	}
}

func TestTrafficDocumentActivationAndReloadKeepDurableProvenance(t *testing.T) {
	trafficControlPlaneMu.Lock()
	previousManaged, previousDoc, previousActivator := trafficControlPlaneManaged, trafficControlLatestDoc, trafficControlActivator
	trafficControlActivator = nil
	trafficControlPlaneMu.Unlock()
	configMu.Lock()
	previousGlobal := GlobalConfig
	GlobalConfig = nil
	configMu.Unlock()
	t.Cleanup(func() {
		trafficControlPlaneMu.Lock()
		trafficControlPlaneManaged, trafficControlLatestDoc, trafficControlActivator = previousManaged, previousDoc, previousActivator
		trafficControlPlaneMu.Unlock()
		configMu.Lock()
		GlobalConfig = previousGlobal
		configMu.Unlock()
	})
	document := TrafficControlDocument{Revision: 12, Config: sections.SectionConfig{Enabled: true, ProtectionLevel: 4, Settings: map[string]interface{}{"geo": map[string]interface{}{"enabled": false}}}}
	bootstrap := &Config{}
	if err := applyTrafficControlPlaneDocument(document, bootstrap); err != nil {
		t.Fatal(err)
	}
	section := bootstrap.GetSectionsConfigMap()["traffic_control"]
	metadata, ok := section.Settings["control"].(map[string]interface{})
	if !ok || metadata["revision"] != "pg-12" || !section.Enabled || section.ProtectionLevel != 4 {
		t.Fatalf("activated runtime lost database provenance or policy: %+v", section)
	}
	var observed sections.SectionConfig
	SetTrafficControlRuntimeActivator(func(candidate sections.SectionConfig) error { observed = candidate; return nil })
	if err := ApplyTrafficControlPlaneDocument(document); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observed.Settings["control"], metadata) {
		t.Fatal("runtime reload callback did not receive durable provenance")
	}
	reloaded := &Config{}
	preserveManagedTrafficControl(reloaded)
	if !reflect.DeepEqual(reloaded.Sections.TrafficControl["control"], metadata) {
		t.Fatal("managed configuration reload discarded runtime provenance")
	}
}
