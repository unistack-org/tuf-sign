package tuf

import (
	"encoding/json"
	"testing"
)

func TestCustomImpactParsing(t *testing.T) {
	raw := json.RawMessage(`{
		"version": "1.4.0",
		"critical": true,
		"min_from": "1.2.0",
		"migrations": true,
		"notes_url": "https://unistack.org/notes/1.4.0",
		"impact": {
			"agent_restart": "required",
			"host_reboot": "recommended",
			"vm_restart": "",
			"quantum_flux": "required"
		}
	}`)
	c, err := ParseCustom(raw)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "1.4.0" || !c.Critical || c.MinFrom != "1.2.0" || !c.Migrations {
		t.Fatalf("basic fields: %+v", c)
	}
	if c.NotesURL != "https://unistack.org/notes/1.4.0" {
		t.Fatalf("notes_url: %q", c.NotesURL)
	}
	if c.ImpactOf(ImpactAgentRestart) != LevelRequired {
		t.Fatalf("agent_restart = %q", c.ImpactOf(ImpactAgentRestart))
	}
	if c.ImpactOf(ImpactHostReboot) != LevelRecommended {
		t.Fatalf("host_reboot = %q", c.ImpactOf(ImpactHostReboot))
	}
	if c.ImpactOf(ImpactVMRestart) != LevelNone {
		t.Fatalf("vm_restart explicit empty = %q", c.ImpactOf(ImpactVMRestart))
	}
	// unknown impact keys are kept in the map but must not make ParseCustom fail
	if _, ok := c.Impact["quantum_flux"]; !ok {
		t.Fatal("unknown impact key dropped")
	}
	if !c.HasRequired() {
		t.Fatal("HasRequired false despite agent_restart=required")
	}
}

func TestCustomMissingImpactIsNone(t *testing.T) {
	c, err := ParseCustom(json.RawMessage(`{"version":"1.0.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{ImpactAgentRestart, ImpactHostReboot, ImpactDrain, ImpactVMRestart, ImpactCellMaintenance} {
		if lvl := c.ImpactOf(k); lvl != LevelNone {
			t.Fatalf("impact %s = %q, want none", k, lvl)
		}
	}
	if c.HasRequired() {
		t.Fatal("HasRequired true with no impact")
	}
	// Empty custom parses to zero value.
	if _, err := ParseCustom(nil); err != nil {
		t.Fatalf("nil custom: %v", err)
	}
}

func TestCustomInvalidLevelRejected(t *testing.T) {
	_, err := ParseCustom(json.RawMessage(`{"impact":{"drain":"mandatory"}`))
	if err == nil {
		t.Fatal("invalid impact level accepted")
	}
}

func TestCustomRoundtrip(t *testing.T) {
	in := Custom{
		Version:  "2.0.0",
		Critical: true,
		MinFrom:  "1.5.0",
		Impact:   map[string]Level{ImpactDrain: LevelRequired, ImpactAgentRestart: LevelRecommended},
		Mirrors:  []Mirror{{URL: "https://cdn.unistack.org/tuf", Weight: 3}, {URL: "https://origin.unistack.org/tuf"}},
	}
	raw, err := in.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ParseCustom(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.Version != in.Version || out.Critical != in.Critical || out.MinFrom != in.MinFrom {
		t.Fatalf("roundtrip lost fields: %+v", out)
	}
	if out.ImpactOf(ImpactDrain) != LevelRequired {
		t.Fatalf("drain = %q", out.ImpactOf(ImpactDrain))
	}
	if len(out.Mirrors) != 2 || out.Mirrors[0].Weight != 3 {
		t.Fatalf("mirrors: %+v", out.Mirrors)
	}
}
