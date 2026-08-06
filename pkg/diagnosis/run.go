package diagnosis

import (
	"context"

	"oswbb-analyse/pkg/aitypes"
)

func Run(ctx context.Context, provider Provider, opts aitypes.Options, input Context) AIResult {
	if !opts.Enabled {
		result := DisabledResult()
		result.EvidenceCount = len(input.Evidence)
		return result
	}
	if provider == nil {
		return FallbackResult(aitypes.DefaultModelName(), "AI 服务未配置，请使用 oswbb-analyse-ai 入口", len(input.Evidence))
	}
	return provider.Diagnose(ctx, opts, input)
}

func RunML(ctx context.Context, provider Provider, opts aitypes.Options, input aitypes.MLPromptInput) AIResult {
	if !opts.Enabled {
		result := DisabledResult()
		result.EvidenceCount = len(input.Sections)
		return result
	}
	if provider == nil {
		return FallbackResult(aitypes.DefaultModelName(), "AI 服务未配置，请使用 oswbb-analyse-ai 入口", len(input.Sections))
	}
	return provider.DiagnoseML(ctx, opts, input)
}
