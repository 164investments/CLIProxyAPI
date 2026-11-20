package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type autoResetTestExecutor struct {
	mu           sync.Mutex
	streamFn     func(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error)
	httpFn       func(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error)
	usageChecks  []string
	claimCalls   []autoResetClaimCall
	streamCalls  []string
}

type autoResetClaimCall struct {
	AuthID    string
	Path      string
	Program   string
	GrantID   string
	RequestID string
}

func (e *autoResetTestExecutor) Identifier() string { return "claude" }
func (e *autoResetTestExecutor) Execute(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, errors.New("unexpected Execute")
}
func (e *autoResetTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.mu.Lock()
	e.streamCalls = append(e.streamCalls, auth.ID)
	fn := e.streamFn
	e.mu.Unlock()
	if fn != nil {
		return fn(ctx, auth, req, opts)
	}
	chunks := make(chan cliproxyexecutor.StreamChunk, 1)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"message_start\"}\n\n")}
	close(chunks)
	return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
}
func (e *autoResetTestExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) { return auth, nil }
func (e *autoResetTestExecutor) CountTokens(context.Context, *Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, errors.New("unexpected CountTokens")
}
func (e *autoResetTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	e.mu.Lock()
	if req.Method == http.MethodGet && strings.Contains(req.URL.RawQuery, "cedar_ember=1") {
		e.usageChecks = append(e.usageChecks, auth.ID)
	}
	if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/reset_rate_limits") {
		body, _ := io.ReadAll(req.Body)
		var payload map[string]string
		_ = json.Unmarshal(body, &payload)
		e.claimCalls = append(e.claimCalls, autoResetClaimCall{
			AuthID:    auth.ID,
			Path:      req.URL.Path,
			Program:   payload["program"],
			GrantID:   payload["grant_id"],
			RequestID: payload["request_id"],
		})
	}
	fn := e.httpFn
	e.mu.Unlock()
	if fn != nil {
		return fn(ctx, auth, req)
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("{}"))}, nil
}

func jsonHTTPResponse(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func registerClaudeAutoResetAuth(t *testing.T, m *Manager, id, model, orgUUID string) *Auth {
	t.Helper()
	registry.GetGlobalRegistry().RegisterClient(id, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	auth, err := m.Register(context.Background(), &Auth{
		ID:         id,
		Provider:   "claude",
		Status:     StatusActive,
		Attributes: map[string]string{"auth_kind": AuthKindOAuth},
		Metadata:   map[string]any{"organization_uuid": orgUUID},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}

func enableClaudeAutoReset(m *Manager, minWait string) {
	m.runtimeConfig.Store(&internalconfig.Config{
		Claude: internalconfig.ClaudeConfig{
			AutoResetEnabled: true,
			AutoResetMinWait: minWait,
		},
	})
}

func TestUsageLimitMixedCooldownUsesEarlierUsageReset(t *testing.T) {
	now := time.Date(2026, 11, 20, 2, 13, 41, 0, time.UTC) // 6:13:41 PM PST
	designReset := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC) // 7:00:00 PM PST (~46m away)
	aliciaCooldown := now.Add(4*time.Hour + 36*time.Minute)      // 10:50 PM PST

	for _, affinity := range []bool{false, true} {
		t.Run("affinity="+strconv.FormatBool(affinity), func(t *testing.T) {
			var selector Selector = &WeeklyResetFirstSelector{}
			if affinity {
				wrapped := NewSessionAffinitySelector(selector)
				defer wrapped.Stop()
				selector = wrapped
			}
			manager := NewManager(nil, selector, nil)
			manager.weeklyQuota.nowFunc = func() time.Time { return now }
			design := &Auth{ID: "design", Provider: "claude"}
			alicia := &Auth{
				ID:             "alicia",
				Provider:       "claude",
				Unavailable:    true,
				NextRetryAfter: aliciaCooldown,
				Quota:          QuotaState{Exceeded: true, NextRecoverAt: aliciaCooldown},
			}
			weeklyTestObserve(manager.weeklyQuota, design, now, designReset, 0)
			weeklyTestObserve(manager.weeklyQuota, alicia, now, now.Add(6*24*time.Hour), 73)

			_, _, err := manager.availableAuthsForSelector(selector, []*Auth{design, alicia}, "claude", "claude-opus-5-5", now)
			var cooldown *modelCooldownError
			if !errors.As(err, &cooldown) {
				t.Fatalf("expected modelCooldownError, got %T: %v", err, err)
			}
			wantWait := designReset.Sub(now)
			if cooldown.resetIn != wantWait || !cooldown.usageRecoveryAt.Equal(designReset) {
				t.Fatalf("cooldown = (resetIn=%v, usageRecoveryAt=%v), want (%v, %v)", cooldown.resetIn, cooldown.usageRecoveryAt, wantWait, designReset)
			}
			headers := SafeResponseHeaders(err)
			if got := headers.Get(HeaderAnthropicRatelimitUnifiedReset); got != strconv.FormatInt(designReset.Unix(), 10) {
				t.Fatalf("%s = %q, want %d", HeaderAnthropicRatelimitUnifiedReset, got, designReset.Unix())
			}
			retryAfter, errConv := strconv.Atoi(headers.Get("Retry-After"))
			if errConv != nil || time.Duration(retryAfter)*time.Second > wantWait+time.Second {
				t.Fatalf("Retry-After = %q, want ~%v", headers.Get("Retry-After"), wantWait)
			}
		})
	}
}

func TestLastOpenAccountLongerUpstream429ReportsEarlierPoolReset(t *testing.T) {
	withQuotaCooldownEnabled(t)
	now := time.Now()
	affinity := NewSessionAffinitySelector(&WeeklyResetFirstSelector{})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.weeklyQuota.nowFunc = func() time.Time { return now }

	model := "claude-opus-earlier-pool-reset-test"
	aliciaWait := 4*time.Hour + 36*time.Minute
	designReset := now.Add(46 * time.Minute)
	manager.RegisterExecutor(&customStreamMockExecutor{
		identifier: "claude",
		streamFn: func(_ context.Context, _ *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			return nil, customStatusError{
				code:       http.StatusTooManyRequests,
				msg:        `{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your account's rate limit."}}`,
				retryAfter: &aliciaWait,
			}
		},
	})
	alicia := registerClaudeAutoResetAuth(t, manager, "alicia-open", model, "org-alicia")
	design := registerClaudeAutoResetAuth(t, manager, "design-weekly-out", model, "org-design")
	weeklyTestObserve(manager.weeklyQuota, alicia, now, now.Add(6*24*time.Hour), 73)
	weeklyTestObserve(manager.weeklyQuota, design, now, designReset, 0)

	_, errStream := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if errStream == nil {
		t.Fatal("expected 429 error")
	}
	headers := SafeResponseHeaders(errStream)
	retryAfter, errConv := strconv.Atoi(headers.Get("Retry-After"))
	if errConv != nil || time.Duration(retryAfter)*time.Second > 47*time.Minute {
		t.Fatalf("Retry-After = %q, want ~46m (not 4h36m); err=%v", headers.Get("Retry-After"), errStream)
	}
	if got := headers.Get(HeaderAnthropicRatelimitUnifiedReset); got != strconv.FormatInt(designReset.Unix()+1, 10) && got != strconv.FormatInt(designReset.Unix(), 10) {
		t.Fatalf("%s = %q, want ~%d", HeaderAnthropicRatelimitUnifiedReset, got, designReset.Unix())
	}
}

func TestClaudeAutoResetClaimsFurthestResetAccountAndServesRequest(t *testing.T) {
	now := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	affinity := NewSessionAffinitySelector(&WeeklyResetFirstSelector{})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.weeklyQuota.nowFunc = func() time.Time { return now }
	enableClaudeAutoReset(manager, "3h")

	model := "claude-opus-auto-reset-furthest-test"
	nearReset := now.Add(24 * time.Hour)
	midReset := now.Add(48 * time.Hour)
	furthestReset := now.Add(120 * time.Hour)

	resetDone := false
	exec := &autoResetTestExecutor{
		httpFn: func(_ context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet && strings.Contains(req.URL.RawQuery, "cedar_ember=1") {
				return jsonHTTPResponse(http.StatusOK, `{
					"five_hour": null,
					"seven_day": {"utilization": 100.0, "resets_at": "`+furthestReset.Format(time.RFC3339)+`"},
					"cedar_ember": {
						"eligible": true,
						"at_limit": true,
						"exhausted": ["seven_day", "seven_day_overage_included"],
						"grants": [
							{"id": "full-reset-2611", "resets_left": 1, "ends_at": "2026-12-10T22:00:00Z", "clears": ["seven_day", "seven_day_overage_included"], "paused": false, "usable_now": true, "gives_back_weekly": false},
							{"id": "launch-2610-fable", "resets_left": 1, "ends_at": "2027-03-09T07:59:00Z", "clears": ["seven_day_overage_included"], "paused": false, "usable_now": true, "gives_back_weekly": true}
						]
					}
				}`), nil
			}
			if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/reset_rate_limits") {
				resetDone = true
				return jsonHTTPResponse(http.StatusOK, `{"result":"reset","resets_left":0,"cleared":["seven_day","seven_day_overage_included"]}`), nil
			}
			if req.Method == http.MethodGet && req.URL.Path == "/api/oauth/usage" && resetDone {
				return jsonHTTPResponse(http.StatusOK, `{"seven_day":{"utilization":0.0,"resets_at":"`+furthestReset.Format(time.RFC3339)+`"}}`), nil
			}
			return jsonHTTPResponse(http.StatusInternalServerError, `{}`), nil
		},
	}
	manager.RegisterExecutor(exec)

	near := registerClaudeAutoResetAuth(t, manager, "acct-near", model, "org-near")
	mid := registerClaudeAutoResetAuth(t, manager, "acct-mid", model, "org-mid")
	furthest := registerClaudeAutoResetAuth(t, manager, "acct-furthest", model, "org-furthest")
	weeklyTestObserve(manager.weeklyQuota, near, now, nearReset, 0)
	weeklyTestObserve(manager.weeklyQuota, mid, now, midReset, 0)
	weeklyTestObserve(manager.weeklyQuota, furthest, now, furthestReset, 0)

	result, err := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatalf("ExecuteStream failed after auto-reset: %v", err)
	}
	for range result.Chunks {
	}
	if len(exec.usageChecks) != 1 || exec.usageChecks[0] != furthest.ID {
		t.Fatalf("usageChecks = %v, want [%s]", exec.usageChecks, furthest.ID)
	}
	if len(exec.claimCalls) != 1 {
		t.Fatalf("claimCalls = %+v, want 1", exec.claimCalls)
	}
	claim := exec.claimCalls[0]
	if claim.AuthID != furthest.ID || claim.Path != "/api/organizations/org-furthest/reset_rate_limits" || claim.Program != "cedar_ember" || claim.GrantID != "full-reset-2611" {
		t.Fatalf("unexpected claim = %+v", claim)
	}
	if len(exec.streamCalls) != 1 || exec.streamCalls[0] != furthest.ID {
		t.Fatalf("streamCalls = %v, want [%s]", exec.streamCalls, furthest.ID)
	}
}

func TestClaudeAutoResetDoesNotFallbackWhenFurthestHasNoReset(t *testing.T) {
	now := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	affinity := NewSessionAffinitySelector(&WeeklyResetFirstSelector{})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.weeklyQuota.nowFunc = func() time.Time { return now }
	enableClaudeAutoReset(manager, "3h")

	model := "claude-opus-no-reset-furthest-test"
	nearReset := now.Add(24 * time.Hour)
	furthestReset := now.Add(120 * time.Hour)

	exec := &autoResetTestExecutor{
		httpFn: func(_ context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
			if auth.ID == "acct-furthest" {
				return jsonHTTPResponse(http.StatusOK, `{
					"seven_day": {"utilization": 100.0, "resets_at": "`+furthestReset.Format(time.RFC3339)+`"},
					"cedar_ember": {
						"eligible": true,
						"at_limit": true,
						"exhausted": ["seven_day"],
						"grants": [
							{"id": "full-reset-2611", "resets_left": 0, "clears": ["seven_day"], "paused": false, "usable_now": false, "gives_back_weekly": false}
						]
					}
				}`), nil
			}
			t.Fatalf("unexpected HTTP check for non-furthest account %s", auth.ID)
			return nil, nil
		},
	}
	manager.RegisterExecutor(exec)

	near := registerClaudeAutoResetAuth(t, manager, "acct-near", model, "org-near")
	furthest := registerClaudeAutoResetAuth(t, manager, "acct-furthest", model, "org-furthest")
	weeklyTestObserve(manager.weeklyQuota, near, now, nearReset, 0)
	weeklyTestObserve(manager.weeklyQuota, furthest, now, furthestReset, 0)

	if _, err := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true}); err == nil {
		t.Fatal("expected exhaustion error when furthest account has no reset")
	}
	// Second immediate call should hit negative cache and not re-query Anthropic.
	if _, err := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true}); err == nil {
		t.Fatal("expected exhaustion error on second call")
	}
	if len(exec.usageChecks) != 1 || exec.usageChecks[0] != furthest.ID {
		t.Fatalf("usageChecks = %v, want single check on %s", exec.usageChecks, furthest.ID)
	}
	if len(exec.claimCalls) != 0 {
		t.Fatalf("claimCalls = %+v, want 0", exec.claimCalls)
	}
}

func TestClaudeAutoResetSkipsWhenAnyAccountRecoversWithinMinWait(t *testing.T) {
	now := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	affinity := NewSessionAffinitySelector(&WeeklyResetFirstSelector{})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.weeklyQuota.nowFunc = func() time.Time { return now }
	enableClaudeAutoReset(manager, "3h")

	model := "claude-opus-skip-near-recovery-test"
	exec := &autoResetTestExecutor{
		httpFn: func(_ context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
			t.Fatalf("should not query or claim reset when an account recovers in 2h (< 3h): %s %s", req.Method, req.URL)
			return nil, nil
		},
	}
	manager.RegisterExecutor(exec)

	soon := registerClaudeAutoResetAuth(t, manager, "acct-soon", model, "org-soon")
	furthest := registerClaudeAutoResetAuth(t, manager, "acct-furthest", model, "org-furthest")
	weeklyTestObserve(manager.weeklyQuota, soon, now, now.Add(2*time.Hour), 0)
	weeklyTestObserve(manager.weeklyQuota, furthest, now, now.Add(140*time.Hour), 0)

	if _, err := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true}); err == nil {
		t.Fatal("expected exhaustion error while waiting for 2h recovery")
	}
	if len(exec.usageChecks) != 0 || len(exec.claimCalls) != 0 {
		t.Fatalf("unexpected reset activity: checks=%v claims=%v", exec.usageChecks, exec.claimCalls)
	}
}

func TestClaudeAutoResetMidRequestWhenFurthestWasLastOpenAccount(t *testing.T) {
	withQuotaCooldownEnabled(t)
	now := time.Now()
	affinity := NewSessionAffinitySelector(&WeeklyResetFirstSelector{})
	defer affinity.Stop()
	manager := NewManager(nil, affinity, nil)
	manager.SetRetryConfig(0, 0, 0)
	manager.weeklyQuota.nowFunc = func() time.Time { return now }
	enableClaudeAutoReset(manager, "3h")

	model := "claude-opus-furthest-last-open-test"
	nearReset := now.Add(24 * time.Hour)
	furthestReset := now.Add(140 * time.Hour)
	upstreamWait := 140 * time.Hour

	attempt := 0
	exec := &autoResetTestExecutor{
		streamFn: func(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
			attempt++
			if attempt == 1 {
				return nil, customStatusError{
					code:       http.StatusTooManyRequests,
					msg:        `{"type":"error","error":{"type":"rate_limit_error","message":"This request would exceed your account's rate limit."}}`,
					retryAfter: &upstreamWait,
				}
			}
			chunks := make(chan cliproxyexecutor.StreamChunk, 1)
			chunks <- cliproxyexecutor.StreamChunk{Payload: []byte("data: {\"type\":\"message_start\"}\n\n")}
			close(chunks)
			return &cliproxyexecutor.StreamResult{Chunks: chunks}, nil
		},
		httpFn: func(_ context.Context, _ *Auth, req *http.Request) (*http.Response, error) {
			if req.Method == http.MethodGet && strings.Contains(req.URL.RawQuery, "cedar_ember=1") {
				return jsonHTTPResponse(http.StatusOK, `{
					"seven_day": {"utilization": 100.0, "resets_at": "`+furthestReset.Format(time.RFC3339)+`"},
					"cedar_ember": {
						"eligible": true,
						"at_limit": true,
						"exhausted": ["seven_day"],
						"grants": [
							{"id": "full-reset-2611", "resets_left": 1, "ends_at": "`+now.Add(20*24*time.Hour).Format(time.RFC3339)+`", "clears": ["seven_day"], "paused": false, "usable_now": true, "gives_back_weekly": false}
						]
					}
				}`), nil
			}
			if req.Method == http.MethodPost && strings.HasSuffix(req.URL.Path, "/reset_rate_limits") {
				return jsonHTTPResponse(http.StatusOK, `{"result":"reset","resets_left":0,"cleared":["seven_day"]}`), nil
			}
			return jsonHTTPResponse(http.StatusOK, `{"seven_day":{"utilization":0.0,"resets_at":"`+furthestReset.Format(time.RFC3339)+`"}}`), nil
		},
	}
	manager.RegisterExecutor(exec)

	near := registerClaudeAutoResetAuth(t, manager, "acct-near", model, "org-near")
	furthest := registerClaudeAutoResetAuth(t, manager, "acct-furthest", model, "org-furthest")
	weeklyTestObserve(manager.weeklyQuota, near, now, nearReset, 0)
	weeklyTestObserve(manager.weeklyQuota, furthest, now, furthestReset, 5) // still appears open before upstream 429

	result, err := manager.ExecuteStream(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{Stream: true})
	if err != nil {
		t.Fatalf("ExecuteStream failed: %v", err)
	}
	for range result.Chunks {
	}
	if len(exec.claimCalls) != 1 || exec.claimCalls[0].AuthID != furthest.ID {
		t.Fatalf("claimCalls = %+v, want 1 claim on %s", exec.claimCalls, furthest.ID)
	}
	if len(exec.streamCalls) != 2 || exec.streamCalls[0] != furthest.ID || exec.streamCalls[1] != furthest.ID {
		t.Fatalf("streamCalls = %v, want [%s, %s]", exec.streamCalls, furthest.ID, furthest.ID)
	}
}

func TestSelectClaudeAutoResetGrantPolicies(t *testing.T) {
	now := time.Date(2026, 11, 20, 6, 0, 0, 0, time.UTC)
	soon := now.Add(24 * time.Hour)
	later := now.Add(48 * time.Hour)

	t.Run("five-hour only never consumes weekly reset", func(t *testing.T) {
		usage := claudeCedarEmberUsage{
			Eligible:     true,
			FiveHourUtil: 100,
			SevenDayUtil: 27,
			Exhausted:    map[string]bool{"five_hour": true},
			Grants: []claudeCedarEmberGrant{{
				ID: "full-reset-2611", ResetsLeft: 1, UsableNow: true,
				Clears: []string{"five_hour", "seven_day", "seven_day_overage_included"},
			}},
		}
		if _, ok := selectClaudeAutoResetGrant(usage, "claude-opus-5-5", now); ok {
			t.Fatal("should not consume weekly reset when only five_hour is exhausted")
		}
	})

	t.Run("fable gives_back_weekly fallback when full reset is spent", func(t *testing.T) {
		usage := claudeCedarEmberUsage{
			Eligible:               true,
			SevenDayUtil:           100,
			SevenDayFableUtil:      100,
			FableUsedOfWeeklyShare: 50,
			Exhausted:              map[string]bool{"seven_day": true, "seven_day_overage_included": true},
			Grants: []claudeCedarEmberGrant{
				{ID: "full-reset-2611", ResetsLeft: 0, UsableNow: false, Clears: []string{"seven_day"}},
				{ID: "launch-2610-fable-6mo", ResetsLeft: 1, UsableNow: true, EndsAt: &later, Clears: []string{"seven_day_overage_included"}, GivesBackWeekly: true},
				{ID: "launch-2610-fable", ResetsLeft: 1, UsableNow: true, EndsAt: &soon, Clears: []string{"seven_day_overage_included"}, GivesBackWeekly: true},
			},
		}
		got, ok := selectClaudeAutoResetGrant(usage, "claude-opus-5-5", now)
		if !ok || got.ID != "launch-2610-fable" {
			t.Fatalf("got = (%+v, %v), want launch-2610-fable", got, ok)
		}
	})

	t.Run("fable-only exhaustion never burns full seven_day reset", func(t *testing.T) {
		usage := claudeCedarEmberUsage{
			Eligible:          true,
			SevenDayUtil:      40,
			SevenDayFableUtil: 100,
			Exhausted:         map[string]bool{"seven_day_overage_included": true},
			Grants: []claudeCedarEmberGrant{
				{ID: "full-reset-2611", ResetsLeft: 1, UsableNow: true, Clears: []string{"seven_day", "seven_day_overage_included"}},
			},
		}
		if got, ok := selectClaudeAutoResetGrant(usage, "claude-fable-5-2", now); ok {
			t.Fatalf("should not burn full weekly reset for fable-only exhaustion, got %+v", got)
		}
	})

	t.Run("fable-only exhaustion uses fable-specific reset", func(t *testing.T) {
		usage := claudeCedarEmberUsage{
			Eligible:          true,
			SevenDayUtil:      40,
			SevenDayFableUtil: 100,
			Exhausted:         map[string]bool{"seven_day_overage_included": true},
			Grants: []claudeCedarEmberGrant{
				{ID: "full-reset-2611", ResetsLeft: 1, UsableNow: true, Clears: []string{"seven_day", "seven_day_overage_included"}},
				{ID: "launch-2610-fable", ResetsLeft: 1, UsableNow: true, Clears: []string{"seven_day_overage_included"}, GivesBackWeekly: true},
			},
		}
		got, ok := selectClaudeAutoResetGrant(usage, "claude-fable-5-2", now)
		if !ok || got.ID != "launch-2610-fable" {
			t.Fatalf("got = (%+v, %v), want launch-2610-fable", got, ok)
		}
	})
}
