package diagnosis

import (
	"context"

	"oswbb-analyse/pkg/aitypes"
)

type Provider interface {
	Diagnose(context.Context, aitypes.Options, Context) AIResult
	DiagnoseML(context.Context, aitypes.Options, aitypes.MLPromptInput) AIResult
}
