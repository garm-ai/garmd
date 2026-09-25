package record

import (
	"context"
	"github.com/garm-ai/garm/contracts/ledger"
	"log/slog"
)

// SlogRecorder is the degraded mode of spec §3/§7: without DATABASE_URL,
// usage events land as structured logs flagged unledgered=true.
type Slog struct {
	l *slog.Logger
}

func NewSlog(l *slog.Logger) *Slog { return &Slog{l: l} }

func (r *Slog) Record(ctx context.Context, ev ledger.Event) {
	violations := ev.PolicyViolations
	if violations == nil {
		violations = []string{} // JSON [] not null — the e2e asserts == []
	}
	attrs := []slog.Attr{
		slog.Bool("unledgered", true),
		slog.String("tenant", ev.Tenant),
		slog.String("app", ev.App),
		slog.String("feature", ev.Feature),
		slog.String("run_id", ev.RunID),
		slog.String("correlation_id", ev.CorrelationID),
		slog.String("causation_id", ev.CausationID),
		slog.String("prompt_name", ev.PromptName),
		slog.String("prompt_hash", ev.PromptHash),
		slog.String("alias", ev.Alias),
		slog.String("resolved_model", ev.ResolvedModel),
		slog.Bool("model_overridden", ev.ModelOverridden),
		slog.Int64("input_tokens", ev.Usage.InputTokens),
		slog.Int64("output_tokens", ev.Usage.OutputTokens),
		slog.Int64("cached_tokens", ev.Usage.CachedTokens),
		slog.Int64("reasoning_tokens", ev.Usage.ReasoningTokens),
		slog.Float64("cost_usd", ev.CostUSD),
		slog.String("cost_source", ev.CostSource),
		slog.Int64("latency_ms", ev.LatencyMS),
		slog.String("provider_request_id", ev.ProviderRequestID),
		slog.Bool("fallback_used", ev.FallbackUsed),
		slog.String("outcome", string(ev.Outcome)),
		slog.String("error_kind", ev.ErrorKind),
		// See meter.Event.ErrorDetail: unsanitized free text, ledger only.
		slog.String("error_detail", ev.ErrorDetail),
		slog.String("policy_mode", ev.PolicyMode),
		slog.Any("policy_violations", violations),
	}
	if ev.Tool != "" {
		attrs = append(attrs,
			slog.String("tool", ev.Tool),
			slog.String("principal_subject", ev.PrincipalSubject),
			slog.String("principal_actor", ev.PrincipalActor),
			slog.String("principal_kind", ev.PrincipalKind),
			slog.Int("chain_depth", ev.ChainDepth),
			slog.String("clearance_effective", ev.ClearanceEffective),
			slog.Any("compartments_effective", ev.CompartmentsEffective),
			slog.String("redaction_plan", ev.RedactionPlan),
			slog.Int("redaction_count", ev.RedactionCount),
			slog.Int("disclosed_count", ev.DisclosedCount),
		)
	}
	// context.WithoutCancel: a cancelled request must still record.
	r.l.LogAttrs(context.WithoutCancel(ctx), slog.LevelInfo, "garm.usage", attrs...)
}
