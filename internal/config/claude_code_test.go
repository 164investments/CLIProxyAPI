package config

import (
	"testing"
	"time"
)

func TestParseConfigBytesClaudeCodeModelListCloaking(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "defaults to enabled cloaking",
			yaml: "port: 8317\n",
			want: false,
		},
		{
			name: "disables model list cloaking",
			yaml: "claude-code:\n  disable-cloaking-model-list: true\n",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, errParse := ParseConfigBytes([]byte(tt.yaml))
			if errParse != nil {
				t.Fatalf("ParseConfigBytes() error = %v", errParse)
			}
			if got := cfg.ClaudeCode.DisableCloakingModelList; got != tt.want {
				t.Fatalf("DisableCloakingModelList = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestParseConfigBytesClaudeModelLevelCooling(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want bool
	}{
		{
			name: "defaults to false",
			yaml: "port: 8317\n",
			want: false,
		},
		{
			name: "enables model-level cooling",
			yaml: "claude:\n  model-level-cooling: true\n",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, errParse := ParseConfigBytes([]byte(tt.yaml))
			if errParse != nil {
				t.Fatalf("ParseConfigBytes() error = %v", errParse)
			}
			if got := cfg.Claude.ModelLevelCooling; got != tt.want {
				t.Fatalf("cfg.Claude.ModelLevelCooling = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestParseConfigBytesClaudeAutoReset(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		wantEnabled bool
		wantMinWait time.Duration
	}{
		{
			name:        "defaults to disabled with 3h min wait",
			yaml:        "config-version: 8\n",
			wantEnabled: false,
			wantMinWait: 3 * time.Hour,
		},
		{
			name:        "v8 upstream.claude enables auto-reset with custom wait",
			yaml:        "config-version: 8\nupstream:\n  claude:\n    auto-reset-enabled: true\n    auto-reset-min-wait: \"4h\"\n",
			wantEnabled: true,
			wantMinWait: 4 * time.Hour,
		},
		{
			name:        "v8 upstream.claude defaults invalid wait to 3h",
			yaml:        "config-version: 8\nupstream:\n  claude:\n    auto-reset-enabled: true\n    auto-reset-min-wait: \"bad\"\n",
			wantEnabled: true,
			wantMinWait: 3 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, errParse := ParseConfigBytes([]byte(tt.yaml))
			if errParse != nil {
				t.Fatalf("ParseConfigBytes() error = %v", errParse)
			}
			if cfg.Claude.AutoResetEnabled != tt.wantEnabled {
				t.Fatalf("AutoResetEnabled = %t, want %t", cfg.Claude.AutoResetEnabled, tt.wantEnabled)
			}
			if got := cfg.Claude.EffectiveAutoResetMinWait(); got != tt.wantMinWait {
				t.Fatalf("EffectiveAutoResetMinWait() = %v, want %v", got, tt.wantMinWait)
			}
		})
	}
}
