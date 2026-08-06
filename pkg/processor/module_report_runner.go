package processor

import (
	"context"

	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
)

type ModuleReportRunner interface {
	BuildModuleReport(ctx context.Context, fileType core.FileType, bundle *core.AnalysisBundle, timeRange core.TimeRange, cfg config.Config, aiDiagnosis diagnosis.AIResult) (*report.Report, error)
}

func (fp *FileProcessor) SetModuleReportRunner(r ModuleReportRunner) {
	fp.reportRunner = r
}
