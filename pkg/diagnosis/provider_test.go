package diagnosis

import (
	"context"
	"testing"

	"oswbb-analyse/pkg/aitypes"
)

type providerStub struct{}

func (providerStub) Diagnose(context.Context, aitypes.Options, Context) AIResult {
	return DisabledResult()
}

func (providerStub) DiagnoseML(context.Context, aitypes.Options, aitypes.MLPromptInput) AIResult {
	return DisabledResult()
}

func TestProviderInterfaceAcceptsLocalDiagnosisMethods(t *testing.T) {
	var provider Provider = providerStub{}

	if got := provider.Diagnose(context.Background(), aitypes.Options{}, Context{}); got.Status != AIStatusDisabled {
		t.Fatalf("Diagnose status = %q, want disabled", got.Status)
	}
	if got := provider.DiagnoseML(context.Background(), aitypes.Options{}, aitypes.MLPromptInput{}); got.Status != AIStatusDisabled {
		t.Fatalf("DiagnoseML status = %q, want disabled", got.Status)
	}
}
