package app

import (
	"context"
	"time"

	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/modules"
	"oswbb-analyse/internal/report"
)

type ModuleRunner interface {
	Name() modules.ModuleName
	FileTypes() []core.FileType
	Run(ctx context.Context, req ModuleRequest) (*report.Report, error)
}

type ModuleDescriptor struct {
	Name         modules.ModuleName
	FileTypes    []core.FileType
	MaxTimeRange time.Duration
	Runner       ModuleRunner
}
