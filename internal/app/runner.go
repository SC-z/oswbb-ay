package app

import (
	"context"
	"os"
	"oswbb-analyse/internal/apperr"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/internal/report"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/processor"
	"time"
)

// pathProcessor is the narrow adapter needed by the app layer.
// Keeping this interface private prevents new callers from depending on the
// legacy processor shape while still allowing tests and the AI entrypoint to
// inject the current implementation.
// pkg/processor is currently a compatibility backend for parsing, legacy
// output side effects, and AI bundle wiring; registry-owned module runners are
// the new app-facing boundary.
type pathProcessor interface {
	ProcessPath(inputPath, startTimeStr, endTimeStr string, singleMode bool, outputFormat string, cst *time.Location, aiConfig processor.AIConfig) error
}

type moduleReportRunnerSetter interface {
	SetModuleReportRunner(processor.ModuleReportRunner)
}

type outputSinkSetter interface {
	SetOutputSink(internaloutput.OutputSink)
}

type diagnosisProviderSetter interface {
	SetDiagnosisProvider(diagnosis.Provider)
}

// Options captures the current CLI contract without forcing a processor rewrite.
type Options struct {
	InputPath string
	// OutputPath is reserved for the future output layer split; legacy code
	// still derives filenames inside pkg/processor.
	OutputPath string
	StartTime  string
	EndTime    string
	SingleMode bool
	// OutputFormat keeps the public CLI values stable: report, csv, json, ml, html.
	OutputFormat string
	// EnableAI is the app-level switch. The detailed AI knobs remain in AIConfig.
	EnableAI bool
	AIConfig processor.AIConfig
	// Location lets tests and alternate entrypoints override the legacy CST default.
	Location *time.Location
	Config   config.Config
	Registry *Registry
	// OutputSink is the narrow app-to-side-effect boundary. Nil uses the
	// legacy file/stdout sink.
	OutputSink        OutputSink
	DiagnosisProvider diagnosis.Provider
}

// Runner is the future application workflow boundary.
type Runner struct {
	Options   Options
	processor pathProcessor
}

func NewRunner(opts Options) *Runner {
	return NewRunnerWithProcessor(opts, processor.NewFileProcessorWithConfig(effectiveConfig(opts.Config)))
}

func NewRunnerWithProcessor(opts Options, fp pathProcessor) *Runner {
	return &Runner{
		Options:   opts,
		processor: fp,
	}
}

func (r *Runner) Run() error {
	opts := r.Options
	cfg := effectiveConfig(opts.Config)
	if err := cfg.Validate(); err != nil {
		return apperr.Wrap(apperr.KindConfig, "", "validate config", err)
	}
	registry, err := effectiveRegistry(opts.Registry)
	if err != nil {
		return apperr.Wrap(apperr.KindInternal, "", "build module registry", err)
	}
	if err := validateInputModules(opts.InputPath, registry); err != nil {
		return err
	}
	location := opts.Location
	if location == nil {
		location = time.FixedZone("CST", 8*3600)
	}

	outputFormat := opts.OutputFormat
	if outputFormat == "" {
		outputFormat = cfg.General.DefaultOutputFormat
	}

	aiConfig := opts.AIConfig
	if opts.EnableAI {
		aiConfig.Enabled = true
	}

	fp := r.processor
	if fp == nil {
		fp = processor.NewFileProcessorWithConfig(cfg)
	}
	if setter, ok := fp.(moduleReportRunnerSetter); ok {
		setter.SetModuleReportRunner(registryReportRunner{registry: registry})
	}
	if setter, ok := fp.(outputSinkSetter); ok {
		setter.SetOutputSink(effectiveOutputSink(opts.OutputSink))
	}
	if setter, ok := fp.(diagnosisProviderSetter); ok && opts.DiagnosisProvider != nil {
		setter.SetDiagnosisProvider(opts.DiagnosisProvider)
	}
	if err := fp.ProcessPath(opts.InputPath, opts.StartTime, opts.EndTime, opts.SingleMode, outputFormat, location, aiConfig); err != nil {
		if apperr.KindOf(err) != "" {
			return err
		}
		return apperr.Wrap(apperr.KindAnalysis, "", "process input", err)
	}
	return nil
}

type registryReportRunner struct {
	registry *Registry
}

func (r registryReportRunner) BuildModuleReport(ctx context.Context, fileType core.FileType, bundle *core.AnalysisBundle, timeRange core.TimeRange, cfg config.Config, aiDiagnosis diagnosis.AIResult) (*report.Report, error) {
	desc, err := r.registry.Resolve(fileType)
	if err != nil {
		return nil, err
	}
	return desc.Runner.Run(ctx, ModuleRequest{
		Bundle:    bundle,
		TimeRange: timeRange,
		Config:    cfg,
		Diagnosis: aiDiagnosis,
	})
}

func effectiveRegistry(registry *Registry) (*Registry, error) {
	if registry != nil {
		return registry, nil
	}
	return NewBuiltinRegistry()
}

func validateInputModules(inputPath string, registry *Registry) error {
	fileTypes, err := core.FileTypesForPath(inputPath)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return apperr.Wrap(apperr.KindIO, "", "access input path", err)
		}
		return apperr.Wrap(apperr.KindIO, "", "inspect input path", err)
	}
	for _, fileType := range fileTypes {
		if _, err := registry.Resolve(fileType); err != nil {
			return apperr.Wrap(apperr.KindAnalysis, string(fileType), "resolve module", err)
		}
	}
	return nil
}

func effectiveConfig(cfg config.Config) config.Config {
	if cfg == (config.Config{}) {
		return config.Default()
	}
	return cfg
}

func effectiveOutputSink(sink OutputSink) internaloutput.OutputSink {
	if sink != nil {
		return sink
	}
	return internaloutput.FileSink{}
}
