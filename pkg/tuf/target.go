package tuf

import (
	"encoding/json"
	"fmt"
)

// Impact keys describe what applying an update costs. Publishers set
// them in target custom metadata; unknown keys are ignored on purpose
// so new impact types can be added without breaking old agents.
const (
	ImpactAgentRestart    = "agent_restart"    // cell/agent process restarts
	ImpactHostReboot      = "host_reboot"      // host must reboot
	ImpactDrain           = "drain"            // VMs must be evacuated first
	ImpactVMRestart       = "vm_restart"       // guest inside the VM restarts
	ImpactCellMaintenance = "cell_maintenance" // cell enters maintenance
)

// Level is the severity of an impact. Absence of a key means LevelNone.
type Level string

const (
	LevelNone        Level = ""
	LevelRecommended Level = "recommended"
	LevelRequired    Level = "required"
)

// Valid reports whether l is a known impact level.
func (l Level) Valid() bool {
	switch l {
	case LevelNone, LevelRecommended, LevelRequired:
		return true
	}
	return false
}

func (l Level) String() string {
	if l == LevelNone {
		return "none"
	}
	return string(l)
}

// Custom is the "custom" object of every release target.
type Custom struct {
	Version    string           `json:"version"`
	Critical   bool             `json:"critical,omitempty"`
	MinFrom    string           `json:"min_from,omitempty"` // oldest version this update applies from
	Migrations bool             `json:"migrations,omitempty"`
	NotesURL   string           `json:"notes_url,omitempty"`
	Impact     map[string]Level `json:"impact,omitempty"`
	Mirrors    []Mirror         `json:"mirrors,omitempty"`
}

// ParseCustom decodes target custom metadata. Missing impact keys
// read as none; unknown impact keys are ignored; invalid levels are
// rejected.
func ParseCustom(raw json.RawMessage) (Custom, error) {
	c := Custom{}
	if len(raw) == 0 {
		return c, nil
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return c, fmt.Errorf("tuf: target custom: %w", err)
	}
	for k, lvl := range c.Impact {
		if !lvl.Valid() {
			return c, fmt.Errorf("tuf: target custom: impact %q has invalid level %q", k, lvl)
		}
	}
	return c, nil
}

// ImpactOf returns the severity of one impact key (none when absent).
func (c Custom) ImpactOf(key string) Level {
	return c.Impact[key]
}

// HasRequired reports whether any known impact is "required".
func (c Custom) HasRequired() bool {
	for _, lvl := range c.Impact {
		if lvl == LevelRequired {
			return true
		}
	}
	return false
}

// Marshal encodes the custom object for publishing.
func (c Custom) Marshal() (json.RawMessage, error) {
	return json.Marshal(c)
}
