package diagnosis

import (
	"context"
	"strings"
	"testing"

	"oswbb-analyse/pkg/aitypes"
)

type countingProvider struct {
	calls int
}

func (p *countingProvider) Diagnose(context.Context, aitypes.Options, Context) AIResult {
	p.calls++
	return ActiveResult("model", "runtime", "ok", nil, 1)
}

func (p *countingProvider) DiagnoseML(context.Context, aitypes.Options, aitypes.MLPromptInput) AIResult {
	p.calls++
	return ActiveResult("model", "runtime", "ml ok", nil, 1)
}

func TestRunDisabledDoesNotCallProvider(t *testing.T) {
	provider := &countingProvider{}

	got := Run(context.Background(), provider, aitypes.Options{}, Context{Evidence: []Evidence{{ID: "e1"}}})

	if got.Status != AIStatusDisabled {
		t.Fatalf("status = %q, want disabled", got.Status)
	}
	if provider.calls != 0 {
		t.Fatalf("provider should not be called when disabled")
	}
}

func TestRunEnabledWithoutProviderReturnsFallback(t *testing.T) {
	got := Run(context.Background(), nil, aitypes.Options{Enabled: true}, Context{Evidence: []Evidence{{ID: "e1"}}})

	if got.Status != AIStatusFallback {
		t.Fatalf("status = %q, want fallback", got.Status)
	}
	if !strings.Contains(got.FallbackReason, "AI 服务未配置") {
		t.Fatalf("fallback reason = %q", got.FallbackReason)
	}
}

func TestRunEnabledUsesProvider(t *testing.T) {
	provider := &countingProvider{}

	got := Run(context.Background(), provider, aitypes.Options{Enabled: true}, Context{Evidence: []Evidence{{ID: "e1"}}})

	if got.Status != AIStatusActive || provider.calls != 1 {
		t.Fatalf("Run status=%q calls=%d, want active and one call", got.Status, provider.calls)
	}
}

func TestRunMLEnabledUsesProvider(t *testing.T) {
	provider := &countingProvider{}

	got := RunML(context.Background(), provider, aitypes.Options{Enabled: true}, aitypes.MLPromptInput{
		Sections: []aitypes.MLSection{{ID: "ml"}},
	})

	if got.Status != AIStatusActive || provider.calls != 1 {
		t.Fatalf("RunML status=%q calls=%d, want active and one call", got.Status, provider.calls)
	}
}
