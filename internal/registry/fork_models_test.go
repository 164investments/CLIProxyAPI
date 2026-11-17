package registry

import (
	"bytes"
	"encoding/json"
	"testing"
)

func modelIDs(models []*ModelInfo) map[string]*ModelInfo {
	out := make(map[string]*ModelInfo, len(models))
	for _, m := range models {
		out[m.ID] = m
	}
	return out
}

func TestEmbeddedCatalogIncludesForkCodexModels(t *testing.T) {
	data := getModels()
	for name, section := range map[string][]*ModelInfo{
		"codex-team": data.CodexTeam,
		"codex-plus": data.CodexPlus,
		"codex-pro":  data.CodexPro,
	} {
		if _, ok := modelIDs(section)["gpt-6.2-sol"]; !ok {
			t.Fatalf("%s is missing gpt-6.2-sol", name)
		}
	}
	if _, ok := modelIDs(data.CodexFree)["gpt-6.2-sol"]; ok {
		t.Fatalf("codex-free should not list gpt-6.2-sol")
	}
}

func TestApplyForkModelsKeepsUpstreamDefinition(t *testing.T) {
	upstream := &ModelInfo{ID: "gpt-6.2-sol", DisplayName: "Upstream"}
	data := &staticModelsJSON{CodexPro: []*ModelInfo{upstream}}
	applyForkModels(data)
	applyForkModels(data)

	count := 0
	for _, m := range data.CodexPro {
		if m.ID == "gpt-6.2-sol" {
			count++
			if m.DisplayName != "Upstream" {
				t.Fatalf("overlay replaced the upstream definition: %q", m.DisplayName)
			}
		}
	}
	if count != 1 {
		t.Fatalf("gpt-6.2-sol listed %d times, want 1", count)
	}
	if _, ok := modelIDs(data.CodexTeam)["gpt-6.2-sol"]; !ok {
		t.Fatalf("overlay was not added to codex-team")
	}
}

func TestCodexClientCatalogIncludesForkModels(t *testing.T) {
	var payload codexClientModelsPayload
	if err := json.Unmarshal(GetCodexClientModelsJSON(), &payload); err != nil {
		t.Fatalf("decode catalog: %v", err)
	}
	slugs := map[string]bool{}
	for _, m := range payload.Models {
		slugs[m["slug"].(string)] = true
	}
	if !slugs["gpt-6.2-sol"] || !slugs["gpt-6.1-sol"] {
		t.Fatalf("catalog slugs = %v, want gpt-6.2-sol and gpt-6.1-sol", slugs)
	}
}

func TestApplyForkCodexClientModelsIsNoOpWhenUpstreamHasSlug(t *testing.T) {
	merged, err := applyForkCodexClientModels(embeddedCodexClientModelsJSON)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if bytes.Equal(merged, embeddedCodexClientModelsJSON) {
		t.Fatalf("expected the overlay to add gpt-6.2-sol to the embedded catalog")
	}
	again, err := applyForkCodexClientModels(merged)
	if err != nil {
		t.Fatalf("apply twice: %v", err)
	}
	if !bytes.Equal(again, merged) {
		t.Fatalf("second apply changed a catalog that already lists the overlay models")
	}
	if err = ValidateCodexClientModelsJSON(merged); err != nil {
		t.Fatalf("merged catalog invalid: %v", err)
	}
}
