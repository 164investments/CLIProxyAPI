package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Fork-only model additions. The upstream catalogs (embedded and remote) replace
// each other wholesale, so a model OpenAI has released but upstream has not
// listed yet would disappear at the next refresh. These overlays add such models
// to every loaded catalog, and only while that catalog lacks them: once upstream
// lists a model, the upstream definition wins and the overlay entry is ignored.

//go:embed models/fork_models.json
var forkModelsJSON []byte

//go:embed models/fork_codex_client_models.json
var forkCodexClientModelsJSON []byte

// applyForkModels adds overlay models to catalog sections that lack them.
func applyForkModels(data *staticModelsJSON) {
	if data == nil {
		return
	}
	var overlay staticModelsJSON
	if err := json.Unmarshal(forkModelsJSON, &overlay); err != nil {
		log.Warnf("registry: failed to parse fork_models.json: %v", err)
		return
	}
	pairs := []struct {
		target *[]*ModelInfo
		extra  []*ModelInfo
	}{
		{&data.Claude, overlay.Claude},
		{&data.Gemini, overlay.Gemini},
		{&data.Vertex, overlay.Vertex},
		{&data.AIStudio, overlay.AIStudio},
		{&data.CodexFree, overlay.CodexFree},
		{&data.CodexTeam, overlay.CodexTeam},
		{&data.CodexPlus, overlay.CodexPlus},
		{&data.CodexPro, overlay.CodexPro},
		{&data.Kimi, overlay.Kimi},
		{&data.Antigravity, overlay.Antigravity},
		{&data.XAI, overlay.XAI},
		{&data.Devin, overlay.Devin},
		{&data.Meta, overlay.Meta},
	}
	for _, p := range pairs {
		*p.target = appendMissingModels(*p.target, p.extra)
	}
}

func appendMissingModels(models, extra []*ModelInfo) []*ModelInfo {
	if len(extra) == 0 {
		return models
	}
	seen := make(map[string]struct{}, len(models))
	for _, m := range models {
		if m != nil {
			seen[strings.ToLower(strings.TrimSpace(m.ID))] = struct{}{}
		}
	}
	for _, m := range extra {
		if m == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(m.ID))
		if _, ok := seen[key]; ok || key == "" {
			continue
		}
		seen[key] = struct{}{}
		models = append(models, m)
	}
	return models
}

// applyForkCodexClientModels returns the Codex client catalog with overlay
// models added in front when their slug is missing. When nothing is added the
// input bytes are returned unchanged.
func applyForkCodexClientModels(data []byte) ([]byte, error) {
	var overlay struct {
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(forkCodexClientModelsJSON, &overlay); err != nil {
		return nil, fmt.Errorf("decode fork Codex client models: %w", err)
	}
	if len(overlay.Models) == 0 {
		return data, nil
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("decode Codex client model catalog: %w", err)
	}
	var models []json.RawMessage
	if raw, ok := top["models"]; ok {
		if err := json.Unmarshal(raw, &models); err != nil {
			return nil, fmt.Errorf("decode Codex client model catalog models: %w", err)
		}
	}

	seen := make(map[string]struct{}, len(models))
	for _, raw := range models {
		seen[codexClientModelSlug(raw)] = struct{}{}
	}
	var added []json.RawMessage
	for _, raw := range overlay.Models {
		slug := codexClientModelSlug(raw)
		if _, ok := seen[slug]; ok || slug == "" {
			continue
		}
		seen[slug] = struct{}{}
		added = append(added, raw)
	}
	if len(added) == 0 {
		return data, nil
	}

	merged, err := json.Marshal(append(added, models...))
	if err != nil {
		return nil, fmt.Errorf("encode Codex client model catalog models: %w", err)
	}
	top["models"] = merged
	out, err := json.Marshal(top)
	if err != nil {
		return nil, fmt.Errorf("encode Codex client model catalog: %w", err)
	}
	return out, nil
}

func codexClientModelSlug(raw json.RawMessage) string {
	var model struct {
		Slug string `json:"slug"`
	}
	if err := json.Unmarshal(raw, &model); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(model.Slug))
}
