package app

import (
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	"oswbb-analyse/pkg/diagnosis"
)

type ModuleRequest struct {
	Bundle    *core.AnalysisBundle
	TimeRange core.TimeRange
	Config    config.Config
	Diagnosis diagnosis.AIResult
}
