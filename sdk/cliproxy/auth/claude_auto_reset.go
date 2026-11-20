package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

const (
	claudeCedarEmberUsageEndpoint = "https://api.anthropic.com/api/oauth/usage?cedar_ember=1&skip_spend=1"
	claudeResetRateLimitsBaseURL  = "https://api.anthropic.com/api/organizations/"
	claudeCedarEmberProgram       = "cedar_ember"
	claudeAutoResetHTTPTimeout    = 15 * time.Second
	claudeAutoResetNegativeTTL    = 15 * time.Minute
	claudeAutoResetCooldownTTL    = 10 * time.Minute
)

var (
	claudeCedarEmberGrantIDPattern   = regexp.MustCompile(`^[a-z0-9_-]{1,40}$`)
	claudeCedarEmberRequestIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	claudeOrgUUIDSafePattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

type claudeAutoResetState struct {
	mu             sync.Mutex
	negativeChecks map[string]time.Time
	lastResetAt    map[string]time.Time
}

func newClaudeAutoResetState() *claudeAutoResetState {
	return &claudeAutoResetState{
		negativeChecks: make(map[string]time.Time),
		lastResetAt:    make(map[string]time.Time),
	}
}

type claudeCedarEmberGrant struct {
	ID              string
	ResetsLeft      int
	EndsAt          *time.Time
	Clears          []string
	Paused          bool
	UsableNow       bool
	PercentUsed     map[string]float64
	GivesBackWeekly bool
}

type claudeCedarEmberUsage struct {
	Eligible               bool
	CooldownUntil          *time.Time
	Exhausted              map[string]bool
	Grants                 []claudeCedarEmberGrant
	FiveHourUtil           float64
	SevenDayUtil           float64
	SevenDayOpusUtil       float64
	SevenDaySonnetUtil     float64
	SevenDayFableUtil      float64
	FableUsedOfWeeklyShare float64
}

func parseClaudeCedarEmberUsage(body []byte) (claudeCedarEmberUsage, error) {
	var out claudeCedarEmberUsage
	if !gjson.ValidBytes(body) {
		return out, fmt.Errorf("invalid cedar_ember usage response")
	}
	root := gjson.ParseBytes(body)
	out.FiveHourUtil = root.Get("five_hour.utilization").Float()
	out.SevenDayUtil = root.Get("seven_day.utilization").Float()
	out.SevenDayOpusUtil = root.Get("seven_day_opus.utilization").Float()
	out.SevenDaySonnetUtil = root.Get("seven_day_sonnet.utilization").Float()

	// Fable weekly_scoped limit in limits[].
	root.Get("limits").ForEach(func(_, lim gjson.Result) bool {
		if strings.EqualFold(lim.Get("scope.model.display_name").String(), "fable") ||
			strings.Contains(strings.ToLower(lim.Get("scope.model.id").String()), "fable") {
			if p := lim.Get("percent").Float(); p > out.SevenDayFableUtil {
				out.SevenDayFableUtil = p
			}
		}
		return true
	})
	root.Get("weekly_scoped_shares").ForEach(func(_, share gjson.Result) bool {
		if p := share.Get("used_percent_of_weekly").Float(); p > out.FableUsedOfWeeklyShare {
			out.FableUsedOfWeeklyShare = p
		}
		return true
	})

	ce := root.Get("cedar_ember")
	if !ce.Exists() || !ce.IsObject() {
		return out, nil
	}
	out.Eligible = ce.Get("eligible").Bool()
	if rawCooldown := strings.TrimSpace(ce.Get("cooldown_until").String()); rawCooldown != "" {
		if parsed, err := time.Parse(time.RFC3339, rawCooldown); err == nil {
			out.CooldownUntil = &parsed
		}
	}
	out.Exhausted = make(map[string]bool)
	ce.Get("exhausted").ForEach(func(_, item gjson.Result) bool {
		if s := strings.TrimSpace(item.String()); s != "" {
			out.Exhausted[s] = true
		}
		return true
	})
	ce.Get("grants").ForEach(func(_, item gjson.Result) bool {
		grant := claudeCedarEmberGrant{
			ID:              strings.TrimSpace(item.Get("id").String()),
			ResetsLeft:      int(item.Get("resets_left").Int()),
			Paused:          item.Get("paused").Bool(),
			UsableNow:       item.Get("usable_now").Bool(),
			GivesBackWeekly: item.Get("gives_back_weekly").Bool(),
			PercentUsed:     make(map[string]float64),
		}
		if rawEnd := strings.TrimSpace(item.Get("ends_at").String()); rawEnd != "" {
			if parsed, err := time.Parse(time.RFC3339, rawEnd); err == nil {
				grant.EndsAt = &parsed
			}
		}
		item.Get("clears").ForEach(func(_, c gjson.Result) bool {
			if s := strings.TrimSpace(c.String()); s != "" {
				grant.Clears = append(grant.Clears, s)
			}
			return true
		})
		item.Get("percent_used").ForEach(func(k, v gjson.Result) bool {
			if key := strings.TrimSpace(k.String()); key != "" && v.Type == gjson.Number {
				grant.PercentUsed[key] = v.Float()
			}
			return true
		})
		if grant.ID != "" {
			out.Grants = append(out.Grants, grant)
		}
		return true
	})
	return out, nil
}

func grantClears(grant claudeCedarEmberGrant, target string) bool {
	for _, c := range grant.Clears {
		if c == target {
			return true
		}
	}
	return false
}

func claudeModelFamily(model string) string {
	lower := strings.ToLower(canonicalModelKey(model))
	switch {
	case strings.Contains(lower, "fable"):
		return "fable"
	case strings.Contains(lower, "opus"):
		return "opus"
	case strings.Contains(lower, "sonnet"):
		return "sonnet"
	default:
		return "all"
	}
}

// claudeUsageWeeklyBlocked reports whether the freshly fetched Anthropic usage
// response shows a weekly limit blocking the requested model (and whether a
// five-hour limit is also active).
func claudeUsageWeeklyBlocked(usage claudeCedarEmberUsage, model string) (weeklyAll, modelWeekly, fiveHour bool) {
	fiveHour = usage.FiveHourUtil >= 100 || usage.Exhausted["five_hour"]
	weeklyAll = usage.SevenDayUtil >= 100 || usage.Exhausted["seven_day"]
	switch claudeModelFamily(model) {
	case "fable":
		modelWeekly = usage.SevenDayFableUtil >= 100 || usage.Exhausted["seven_day_overage_included"]
	case "opus":
		modelWeekly = usage.SevenDayOpusUtil >= 100 || usage.Exhausted["seven_day_opus"]
	case "sonnet":
		modelWeekly = usage.SevenDaySonnetUtil >= 100 || usage.Exhausted["seven_day_sonnet"]
	}
	return weeklyAll, modelWeekly, fiveHour
}

// selectClaudeAutoResetGrant chooses the best usable cedar_ember grant that
// unblocks the requested model on a weekly-exhausted account.
//
// Rules:
//   - Never claims a grant if no weekly limit is blocking the model (so a
//     five-hour-only cooldown never consumes a monthly weekly reset).
//   - If a five-hour limit is also active, requires the grant to clear five_hour.
//   - When seven_day is exhausted, prefers a full weekly grant (clears seven_day),
//     falling back to a Fable grant with gives_back_weekly=true if Fable actually
//     consumed weekly capacity.
//   - When only Fable's scoped weekly bucket is exhausted (seven_day < 100),
//     only considers Fable-specific grants (never burns a full seven_day reset).
//   - Prefers soonest-expiring grants (earliest ends_at) within the same tier.
func selectClaudeAutoResetGrant(usage claudeCedarEmberUsage, model string, now time.Time) (claudeCedarEmberGrant, bool) {
	if !usage.Eligible {
		return claudeCedarEmberGrant{}, false
	}
	if usage.CooldownUntil != nil && usage.CooldownUntil.After(now) {
		return claudeCedarEmberGrant{}, false
	}
	weeklyAll, modelWeekly, fiveHour := claudeUsageWeeklyBlocked(usage, model)
	if !weeklyAll && !modelWeekly {
		return claudeCedarEmberGrant{}, false
	}

	family := claudeModelFamily(model)
	type candidateGrant struct {
		grant claudeCedarEmberGrant
		tier  int
	}
	candidates := make([]candidateGrant, 0, len(usage.Grants))
	for _, g := range usage.Grants {
		if g.ResetsLeft <= 0 || g.Paused || !g.UsableNow {
			continue
		}
		if !claudeCedarEmberGrantIDPattern.MatchString(g.ID) {
			continue
		}
		if g.EndsAt != nil && !g.EndsAt.After(now) {
			continue
		}
		if fiveHour && !grantClears(g, "five_hour") {
			continue
		}
		clearsSevenDay := grantClears(g, "seven_day")
		clearsFable := grantClears(g, "seven_day_overage_included")

		switch {
		case weeklyAll:
			if clearsSevenDay {
				// If Fable is also blocked for a Fable request, make sure it clears Fable too.
				if family == "fable" && modelWeekly && !clearsFable {
					continue
				}
				candidates = append(candidates, candidateGrant{grant: g, tier: 1})
			} else if g.GivesBackWeekly && clearsFable {
				fableUsed := usage.FableUsedOfWeeklyShare > 0 || usage.SevenDayFableUtil > 0 || g.PercentUsed["seven_day_overage_included"] > 0
				if fableUsed {
					candidates = append(candidates, candidateGrant{grant: g, tier: 2})
				}
			}
		case family == "fable" && modelWeekly:
			// Only Fable is exhausted; do not spend a full seven_day reset.
			if clearsFable && !clearsSevenDay {
				candidates = append(candidates, candidateGrant{grant: g, tier: 1})
			}
		case family == "opus" && modelWeekly:
			if grantClears(g, "seven_day_opus") {
				candidates = append(candidates, candidateGrant{grant: g, tier: 1})
			} else if clearsSevenDay {
				candidates = append(candidates, candidateGrant{grant: g, tier: 2})
			}
		case family == "sonnet" && modelWeekly:
			if grantClears(g, "seven_day_sonnet") {
				candidates = append(candidates, candidateGrant{grant: g, tier: 1})
			} else if clearsSevenDay {
				candidates = append(candidates, candidateGrant{grant: g, tier: 2})
			}
		}
	}
	if len(candidates) == 0 {
		return claudeCedarEmberGrant{}, false
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].tier != candidates[j].tier {
			return candidates[i].tier < candidates[j].tier
		}
		ai, aj := candidates[i].grant.EndsAt, candidates[j].grant.EndsAt
		if (ai == nil) != (aj == nil) {
			return ai != nil
		}
		if ai != nil && aj != nil && !ai.Equal(*aj) {
			return ai.Before(*aj)
		}
		return candidates[i].grant.ID < candidates[j].grant.ID
	})
	return candidates[0].grant, true
}

func claudeOrganizationUUID(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if auth.Metadata != nil {
		if raw, ok := auth.Metadata["organization_uuid"].(string); ok {
			if trimmed := strings.TrimSpace(raw); claudeOrgUUIDSafePattern.MatchString(trimmed) {
				return trimmed
			}
		}
	}
	if auth.Attributes != nil {
		if trimmed := strings.TrimSpace(auth.Attributes["organization_uuid"]); claudeOrgUUIDSafePattern.MatchString(trimmed) {
			return trimmed
		}
	}
	return ""
}

func buildClaudeAutoResetRequestID(grantID string, weeklyReset time.Time) string {
	sanitized := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, grantID)
	reqID := fmt.Sprintf("cpa-%s-%d", sanitized, weeklyReset.Unix())
	if len(reqID) > 64 {
		reqID = reqID[:64]
	}
	if !claudeCedarEmberRequestIDPattern.MatchString(reqID) {
		return fmt.Sprintf("cpa-reset-%d", weeklyReset.Unix())
	}
	return reqID
}

func (m *Manager) claudeAuthUpcomingWeeklyReset(auth *Auth, checkModel string, now time.Time) time.Time {
	if auth == nil {
		return time.Time{}
	}
	var allReset, scopedReset time.Time
	if o, ok := m.weeklyQuota.observation(auth); ok && now.Sub(o.ObservedAt) < weeklyQuotaStaleTTL {
		for _, bucket := range o.Buckets {
			if bucket.Window != "weekly" || bucket.ResetAt == nil || !bucket.ResetAt.After(now) {
				continue
			}
			if bucket.Scope == "all" {
				if allReset.IsZero() || bucket.ResetAt.After(allReset) {
					allReset = *bucket.ResetAt
				}
			} else if weeklyBucketApplies(bucket.Scope, checkModel) {
				if scopedReset.IsZero() || bucket.ResetAt.After(scopedReset) {
					scopedReset = *bucket.ResetAt
				}
			}
		}
	}
	if !allReset.IsZero() {
		return allReset
	}
	if !scopedReset.IsZero() {
		return scopedReset
	}
	// Fallback to observed Anthropic-Ratelimit-Unified-7d-Reset signal on auth or model states.
	checkSignals := func(signals map[string]string) {
		for _, key := range []string{"Anthropic-Ratelimit-Unified-7d-Reset", "Anthropic-Ratelimit-Unified-7d_oi-Reset"} {
			raw := strings.TrimSpace(signals[key])
			if raw == "" {
				continue
			}
			sec, err := strconv.ParseInt(raw, 10, 64)
			if err != nil || sec <= 0 {
				continue
			}
			t := time.Unix(sec, 0)
			if t.After(now) && (allReset.IsZero() || t.After(allReset)) {
				allReset = t
			}
		}
	}
	checkSignals(auth.Quota.Signals)
	if checkModel != "" && auth.ModelStates != nil {
		if st := auth.ModelStates[checkModel]; st != nil {
			checkSignals(st.Quota.Signals)
		}
		if st := auth.ModelStates[canonicalModelKey(checkModel)]; st != nil {
			checkSignals(st.Quota.Signals)
		}
	}
	return allReset
}

func providersIncludeClaude(providers []string) bool {
	for _, p := range providers {
		if canonicalSchedulingProvider(p) == "claude" {
			return true
		}
	}
	return false
}

// tryClaudeAutoReset checks whether every candidate Claude OAuth account for
// routeModel is exhausted with no recovery within upstream.claude.auto-reset-min-wait,
// and if so attempts to claim a cedar_ember reset on the single account with the
// furthest upcoming weekly reset date. Returns (authID, true) if an account is
// now ready to serve requests (either freshly reset or already recovered).
func (m *Manager) tryClaudeAutoReset(ctx context.Context, providers []string, routeModel string, opts cliproxyexecutor.Options) (string, bool) {
	if m == nil || m.claudeAutoReset == nil || m.weeklyQuota == nil {
		return "", false
	}
	cfg := m.runtimeConfigSnapshot()
	if cfg == nil || !cfg.Claude.AutoResetEnabled {
		return "", false
	}
	if !providersIncludeClaude(providers) {
		return "", false
	}
	executor := m.executorFor("claude")
	if executor == nil {
		return "", false
	}

	m.claudeAutoReset.mu.Lock()
	defer m.claudeAutoReset.mu.Unlock()

	now := m.weeklyQuota.nowFunc()
	minWait := cfg.Claude.EffectiveAutoResetMinWait()
	eligibility := authSelectionEligibilityForRequest(ctx, opts)
	pinnedAuthID := pinnedAuthIDFromMetadata(opts.Metadata)
	registryRef := registry.GetGlobalRegistry()

	var (
		candidateCount       int
		anyUnknownRecovery   bool
		poolEarliestRecovery time.Time
		furthestAuth         *Auth
		furthestWeeklyReset  time.Time
		furthestCheckModel   string
		alreadyAvailableID   string
	)

	m.mu.RLock()
	for _, candidate := range m.auths {
		if candidate == nil || candidate.Disabled {
			continue
		}
		if canonicalSchedulingProvider(executorKeyFromAuth(candidate)) != "claude" {
			continue
		}
		if candidate.AuthKind() != AuthKindOAuth {
			continue
		}
		if pinnedAuthID != "" && candidate.ID != pinnedAuthID {
			continue
		}
		if !eligibility.allows(candidate) {
			continue
		}
		if routeModel != "" && !m.authSupportsRouteModel(registryRef, candidate, routeModel) {
			continue
		}
		checkModel := m.selectionModelForAuth(candidate, routeModel)
		cap := m.weeklyQuota.capacity(candidate, checkModel, now)
		blocked, reason, cooldownNext := isAuthBlockedForModel(candidate, checkModel, now)
		if reason == blockReasonDisabled {
			continue
		}
		candidateCount++
		if !cap.exhausted && !blocked {
			alreadyAvailableID = candidate.ID
			break
		}

		var recoverAt time.Time
		switch {
		case cap.exhausted && blocked:
			if !cap.recoverAt.IsZero() && !cooldownNext.IsZero() {
				recoverAt = cap.recoverAt
				if cooldownNext.After(recoverAt) {
					recoverAt = cooldownNext
				}
			}
		case cap.exhausted:
			recoverAt = cap.recoverAt
		case blocked:
			recoverAt = cooldownNext
		}
		if recoverAt.IsZero() {
			anyUnknownRecovery = true
		} else if poolEarliestRecovery.IsZero() || recoverAt.Before(poolEarliestRecovery) {
			poolEarliestRecovery = recoverAt
		}

		weeklyReset := m.claudeAuthUpcomingWeeklyReset(candidate, checkModel, now)
		if !weeklyReset.IsZero() {
			if furthestAuth == nil || weeklyReset.After(furthestWeeklyReset) || (weeklyReset.Equal(furthestWeeklyReset) && candidate.ID < furthestAuth.ID) {
				furthestAuth = candidate.Clone()
				furthestWeeklyReset = weeklyReset
				furthestCheckModel = checkModel
			}
		}
	}
	m.mu.RUnlock()

	if alreadyAvailableID != "" {
		return alreadyAvailableID, true
	}
	if candidateCount == 0 || anyUnknownRecovery || poolEarliestRecovery.IsZero() {
		return "", false
	}
	entry := logEntryWithRequestID(ctx)
	waitUntilRecovery := poolEarliestRecovery.Sub(now)
	if waitUntilRecovery < minWait {
		entry.Debugf("claude auto-reset: skipping; earliest account recovers in %s (< %s)", waitUntilRecovery.Round(time.Second), minWait)
		return "", false
	}
	if furthestAuth == nil || furthestWeeklyReset.IsZero() {
		return "", false
	}

	if last := m.claudeAutoReset.lastResetAt[furthestAuth.ID]; !last.IsZero() && now.Sub(last) < claudeAutoResetCooldownTTL {
		return "", false
	}
	negKey := fmt.Sprintf("%s|%d|%s", furthestAuth.ID, furthestWeeklyReset.Unix(), claudeModelFamily(routeModel))
	if until := m.claudeAutoReset.negativeChecks[negKey]; !until.IsZero() && now.Before(until) {
		return "", false
	}
	markNegative := func() {
		m.claudeAutoReset.negativeChecks[negKey] = now.Add(claudeAutoResetNegativeTTL)
	}

	orgUUID := claudeOrganizationUUID(furthestAuth)
	if orgUUID == "" {
		entry.Warnf("claude auto-reset: furthest-reset account %s missing organization_uuid; skipping", formatAuthIdentity(furthestAuth, "claude"))
		markNegative()
		return "", false
	}

	reqCtx, cancel := context.WithTimeout(ctx, claudeAutoResetHTTPTimeout)
	defer cancel()
	if rt := m.roundTripperFor(furthestAuth); rt != nil {
		reqCtx = context.WithValue(reqCtx, roundTripperContextKey{}, rt)
		reqCtx = context.WithValue(reqCtx, "cliproxy.roundtripper", rt)
	}

	// Step 1: Fetch fresh usage + cedar_ember grants for the furthest-reset account.
	usageReq, err := http.NewRequestWithContext(reqCtx, http.MethodGet, claudeCedarEmberUsageEndpoint, nil)
	if err != nil {
		markNegative()
		return "", false
	}
	usageReq.Header.Set("Accept", "application/json")
	usageReq.Header.Set("anthropic-beta", "oauth-2025-04-20")
	usageReq.Header.Set("anthropic-version", "2023-06-01")
	usageResp, err := executor.HttpRequest(reqCtx, furthestAuth, usageReq)
	if usageResp != nil && usageResp.Body != nil {
		defer func() { _ = usageResp.Body.Close() }()
	}
	if err != nil || usageResp == nil || usageResp.Body == nil || usageResp.StatusCode != http.StatusOK {
		status := 0
		if usageResp != nil {
			status = usageResp.StatusCode
		}
		entry.Warnf("claude auto-reset: cedar_ember usage check failed for %s (status=%d err=%v)", formatAuthIdentity(furthestAuth, "claude"), status, err)
		markNegative()
		return "", false
	}
	const maxResetResponseBytes = 1 << 20
	usageBody, err := io.ReadAll(io.LimitReader(usageResp.Body, maxResetResponseBytes+1))
	if err != nil || len(usageBody) > maxResetResponseBytes {
		markNegative()
		return "", false
	}

	// Keep WeeklyQuotaCache fresh with what we just observed.
	if buckets, errParse := parseWeeklyQuota("claude", usageBody, now); errParse == nil {
		m.mu.RLock()
		current := m.auths[furthestAuth.ID]
		if current != nil && current.RegistrationEpoch == furthestAuth.RegistrationEpoch && !current.Disabled {
			m.weeklyQuota.mu.Lock()
			o := m.weeklyQuota.observations[furthestAuth.ID]
			o.Epoch, o.ObservedAt, o.Buckets = furthestAuth.RegistrationEpoch, now, buckets
			m.weeklyQuota.observations[furthestAuth.ID] = o
			m.weeklyQuota.mu.Unlock()
		}
		m.mu.RUnlock()
	}

	parsedUsage, err := parseClaudeCedarEmberUsage(usageBody)
	if err != nil {
		entry.Warnf("claude auto-reset: failed to parse cedar_ember usage for %s: %v", formatAuthIdentity(furthestAuth, "claude"), err)
		markNegative()
		return "", false
	}

	grant, okGrant := selectClaudeAutoResetGrant(parsedUsage, routeModel, now)
	if !okGrant {
		entry.Infof("claude auto-reset: furthest-reset account %s has no usable reset grant for model %q; waiting for normal reset", formatAuthIdentity(furthestAuth, "claude"), routeModel)
		markNegative()
		return "", false
	}

	// Step 2: Claim the selected reset grant.
	requestID := buildClaudeAutoResetRequestID(grant.ID, furthestWeeklyReset)
	claimPayload, err := json.Marshal(map[string]string{
		"program":    claudeCedarEmberProgram,
		"grant_id":   grant.ID,
		"request_id": requestID,
	})
	if err != nil {
		markNegative()
		return "", false
	}
	claimURL := claudeResetRateLimitsBaseURL + orgUUID + "/reset_rate_limits"
	claimReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, claimURL, bytes.NewReader(claimPayload))
	if err != nil {
		markNegative()
		return "", false
	}
	claimReq.Header.Set("Content-Type", "application/json")
	claimReq.Header.Set("Accept", "application/json")
	claimReq.Header.Set("anthropic-beta", "oauth-2025-04-20")
	claimReq.Header.Set("anthropic-version", "2023-06-01")

	claimResp, err := executor.HttpRequest(reqCtx, furthestAuth, claimReq)
	if claimResp != nil && claimResp.Body != nil {
		defer func() { _ = claimResp.Body.Close() }()
	}
	if err != nil || claimResp == nil || claimResp.Body == nil || claimResp.StatusCode != http.StatusOK {
		status := 0
		if claimResp != nil {
			status = claimResp.StatusCode
		}
		entry.Warnf("claude auto-reset: claim failed for %s grant=%q (status=%d err=%v)", formatAuthIdentity(furthestAuth, "claude"), grant.ID, status, err)
		markNegative()
		return "", false
	}
	claimBody, err := io.ReadAll(io.LimitReader(claimResp.Body, maxResetResponseBytes+1))
	if err != nil || len(claimBody) > maxResetResponseBytes || !gjson.ValidBytes(claimBody) {
		markNegative()
		return "", false
	}
	claimResult := strings.TrimSpace(gjson.GetBytes(claimBody, "result").String())
	claimReason := strings.TrimSpace(gjson.GetBytes(claimBody, "reason").String())
	if claimResult != "reset" {
		entry.Warnf("claude auto-reset: claim not applied for %s grant=%q result=%q reason=%q", formatAuthIdentity(furthestAuth, "claude"), grant.ID, claimResult, claimReason)
		markNegative()
		return "", false
	}

	resetsLeft := gjson.GetBytes(claimBody, "resets_left").Int()
	var cleared []string
	gjson.GetBytes(claimBody, "cleared").ForEach(func(_, item gjson.Result) bool {
		if s := strings.TrimSpace(item.String()); s != "" {
			cleared = append(cleared, s)
		}
		return true
	})

	// Step 3: Record success, clear proxy cooldowns, and refresh/invalidate weekly cache.
	m.claudeAutoReset.lastResetAt[furthestAuth.ID] = now
	for k := range m.claudeAutoReset.negativeChecks {
		if strings.HasPrefix(k, furthestAuth.ID+"|") {
			delete(m.claudeAutoReset.negativeChecks, k)
		}
	}
	if _, _, errReset := m.ResetQuota(ctx, furthestAuth.ID); errReset != nil {
		entry.Warnf("claude auto-reset: ResetQuota warning for %s: %v", formatAuthIdentity(furthestAuth, "claude"), errReset)
	}

	// Refresh observed weekly quota immediately; if Anthropic's usage endpoint still
	// briefly reflects pre-reset exhaustion, drop the stale exhausted observation so
	// the reset account can serve requests right away.
	refreshCtx, refreshCancel := context.WithTimeout(context.Background(), claudeAutoResetHTTPTimeout)
	defer refreshCancel()
	m.refreshWeeklyQuota(refreshCtx, furthestAuth)
	if m.weeklyQuota.capacity(furthestAuth, furthestCheckModel, m.weeklyQuota.nowFunc()).exhausted {
		m.weeklyQuota.mu.Lock()
		delete(m.weeklyQuota.observations, furthestAuth.ID)
		m.weeklyQuota.mu.Unlock()
	}

	entry.WithFields(log.Fields{
		"grant_id":               grant.ID,
		"resets_left":            resetsLeft,
		"cleared":                strings.Join(cleared, ","),
		"weekly_reset":           furthestWeeklyReset.Format(time.RFC3339),
		"earliest_pool_recovery": waitUntilRecovery.Round(time.Second).String(),
	}).Infof("claude auto-reset: claimed usage reset for %s", formatAuthIdentity(furthestAuth, "claude"))
	return furthestAuth.ID, true
}
