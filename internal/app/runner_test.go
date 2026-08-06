package app

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"oswbb-analyse/internal/apperr"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	internaloutput "oswbb-analyse/internal/output"
	"oswbb-analyse/pkg/aitypes"
	"oswbb-analyse/pkg/diagnosis"
	"oswbb-analyse/pkg/processor"
	"testing"
	"time"
)

type recordingProcessor struct {
	inputPath    string
	startTime    string
	endTime      string
	singleMode   bool
	outputFormat string
	location     *time.Location
	aiConfig     processor.AIConfig
	err          error
}

type configurableProcessor struct {
	recordingProcessor
	reportRunner processor.ModuleReportRunner
	outputSink   internaloutput.OutputSink
	aiProvider   diagnosis.Provider
}

func (p *configurableProcessor) SetModuleReportRunner(r processor.ModuleReportRunner) {
	p.reportRunner = r
}

func (p *configurableProcessor) SetOutputSink(s internaloutput.OutputSink) {
	p.outputSink = s
}

func (p *configurableProcessor) SetDiagnosisProvider(provider diagnosis.Provider) {
	p.aiProvider = provider
}

type recordingOutputSink struct {
	request internaloutput.OutputRequest
}

func (s *recordingOutputSink) Write(ctx context.Context, req internaloutput.OutputRequest) error {
	s.request = req
	return ctx.Err()
}

type recordingDiagnosisProvider struct{}

func (recordingDiagnosisProvider) Diagnose(context.Context, aitypes.Options, diagnosis.Context) diagnosis.AIResult {
	return diagnosis.DisabledResult()
}

func (recordingDiagnosisProvider) DiagnoseML(context.Context, aitypes.Options, aitypes.MLPromptInput) diagnosis.AIResult {
	return diagnosis.DisabledResult()
}

func (p *recordingProcessor) ProcessPath(inputPath, startTime, endTime string, singleMode bool, outputFormat string, location *time.Location, aiConfig processor.AIConfig) error {
	p.inputPath = inputPath
	p.startTime = startTime
	p.endTime = endTime
	p.singleMode = singleMode
	p.outputFormat = outputFormat
	p.location = location
	p.aiConfig = aiConfig
	return p.err
}

func TestRunnerRunDelegatesToProcessorWithLegacyDefaults(t *testing.T) {
	processorSpy := &recordingProcessor{}
	inputPath := testInputFile(t, "host_iostat.dat")
	runner := NewRunnerWithProcessor(Options{
		InputPath: inputPath,
	}, processorSpy)

	if err := runner.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if processorSpy.inputPath != inputPath {
		t.Fatalf("input path = %q, want %s", processorSpy.inputPath, inputPath)
	}
	if processorSpy.outputFormat != "report" {
		t.Fatalf("output format = %q, want report", processorSpy.outputFormat)
	}
	if processorSpy.location == nil {
		t.Fatalf("location should default to CST")
	}
	_, offset := time.Now().In(processorSpy.location).Zone()
	if offset != 8*3600 {
		t.Fatalf("location offset = %d, want %d", offset, 8*3600)
	}
	if processorSpy.aiConfig.Enabled {
		t.Fatalf("rule runner should keep AI disabled by default")
	}
}

func TestRunnerRunHonorsExplicitOptions(t *testing.T) {
	processorSpy := &recordingProcessor{}
	inputPath := testInputFile(t, "host_meminfo.dat")
	loc := time.FixedZone("TEST", 9*3600)
	runner := NewRunnerWithProcessor(Options{
		InputPath:    inputPath,
		StartTime:    "2026-06-18 10:00:00",
		EndTime:      "2026-06-18 11:00:00",
		SingleMode:   true,
		OutputFormat: "ml",
		Location:     loc,
		EnableAI:     true,
		AIConfig:     processor.AIConfig{Debug: true, ModelPath: "/models/qwen.gguf"},
	}, processorSpy)

	if err := runner.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if processorSpy.startTime != "2026-06-18 10:00:00" || processorSpy.endTime != "2026-06-18 11:00:00" {
		t.Fatalf("time range not forwarded: %q ~ %q", processorSpy.startTime, processorSpy.endTime)
	}
	if !processorSpy.singleMode {
		t.Fatalf("single mode should be forwarded")
	}
	if processorSpy.outputFormat != "ml" {
		t.Fatalf("output format = %q, want ml", processorSpy.outputFormat)
	}
	if processorSpy.location != loc {
		t.Fatalf("location was not forwarded")
	}
	if !processorSpy.aiConfig.Enabled || !processorSpy.aiConfig.Debug || processorSpy.aiConfig.ModelPath != "/models/qwen.gguf" {
		t.Fatalf("AI config not forwarded with EnableAI applied: %+v", processorSpy.aiConfig)
	}
}

func TestRunnerRunRejectsKnownFileTypeMissingFromRegistry(t *testing.T) {
	processorSpy := &recordingProcessor{}
	inputPath := testInputFile(t, "host_top.dat")
	registry := NewRegistry()
	if err := registry.Register(ModuleDescriptor{
		Name:      "only-iostat",
		FileTypes: []core.FileType{core.FileTypeIOStat},
		Runner:    &stubModuleRunner{name: "only-iostat"},
	}); err != nil {
		t.Fatalf("register test module: %v", err)
	}
	runner := NewRunnerWithProcessor(Options{
		InputPath: inputPath,
		Registry:  registry,
	}, processorSpy)

	err := runner.Run()
	if err == nil || !strings.Contains(err.Error(), "unknown file type: top") {
		t.Fatalf("Run error = %v, want unknown top file type", err)
	}
	if processorSpy.inputPath != "" {
		t.Fatalf("processor should not run for unresolved module")
	}
	if apperr.KindOf(err) != apperr.KindAnalysis {
		t.Fatalf("error kind = %q, want analysis", apperr.KindOf(err))
	}
}

func TestRunnerRunWrapsConfigValidationError(t *testing.T) {
	processorSpy := &recordingProcessor{}
	cfg := config.Default()
	cfg.General.DefaultOutputFormat = "bad"
	runner := NewRunnerWithProcessor(Options{
		InputPath: testInputFile(t, "host_iostat.dat"),
		Config:    cfg,
	}, processorSpy)

	err := runner.Run()
	if err == nil {
		t.Fatalf("Run should reject invalid config")
	}
	if apperr.KindOf(err) != apperr.KindConfig {
		t.Fatalf("error kind = %q, want config: %v", apperr.KindOf(err), err)
	}
}

func TestRunnerRunWrapsInputAccessError(t *testing.T) {
	processorSpy := &recordingProcessor{}
	runner := NewRunnerWithProcessor(Options{
		InputPath: filepath.Join(t.TempDir(), "missing_iostat.dat"),
	}, processorSpy)

	err := runner.Run()
	if err == nil {
		t.Fatalf("Run should reject missing input")
	}
	if apperr.KindOf(err) != apperr.KindIO {
		t.Fatalf("error kind = %q, want io: %v", apperr.KindOf(err), err)
	}
}

func TestRunnerRunWrapsProcessorError(t *testing.T) {
	cause := errors.New("legacy analyze failed")
	processorSpy := &recordingProcessor{err: cause}
	runner := NewRunnerWithProcessor(Options{
		InputPath: testInputFile(t, "host_iostat.dat"),
	}, processorSpy)

	err := runner.Run()
	if err == nil {
		t.Fatalf("Run should return processor error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("wrapped error should keep cause: %v", err)
	}
	if apperr.KindOf(err) != apperr.KindAnalysis {
		t.Fatalf("error kind = %q, want analysis: %v", apperr.KindOf(err), err)
	}
}

func TestRunnerRunPreservesClassifiedProcessorError(t *testing.T) {
	cause := errors.New("write denied")
	classified := apperr.Wrap(apperr.KindIO, "iostat", "write output", cause)
	processorSpy := &recordingProcessor{err: classified}
	runner := NewRunnerWithProcessor(Options{
		InputPath: testInputFile(t, "host_iostat.dat"),
	}, processorSpy)

	err := runner.Run()
	if err != classified {
		t.Fatalf("classified processor error should be returned as-is: %v", err)
	}
	if apperr.KindOf(err) != apperr.KindIO {
		t.Fatalf("error kind = %q, want io: %v", apperr.KindOf(err), err)
	}
}

func TestRunnerRunInjectsRegistryReportRunnerIntoProcessor(t *testing.T) {
	processorSpy := &configurableProcessor{}
	runner := NewRunnerWithProcessor(Options{
		InputPath: testInputFile(t, "host_iostat.dat"),
	}, processorSpy)

	if err := runner.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if processorSpy.reportRunner == nil {
		t.Fatalf("runner should inject a registry-backed report runner")
	}
}

func TestRunnerRunInjectsOutputSinkIntoProcessor(t *testing.T) {
	processorSpy := &configurableProcessor{}
	sink := &recordingOutputSink{}
	runner := NewRunnerWithProcessor(Options{
		InputPath:    testInputFile(t, "host_iostat.dat"),
		OutputSink:   sink,
		OutputFormat: "csv",
	}, processorSpy)

	if err := runner.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if processorSpy.outputSink != sink {
		t.Fatalf("runner should inject the configured output sink")
	}
	if processorSpy.outputFormat != "csv" {
		t.Fatalf("output format = %q, want csv", processorSpy.outputFormat)
	}
}

func TestRunnerRunInjectsDiagnosisProviderIntoProcessor(t *testing.T) {
	processorSpy := &configurableProcessor{}
	provider := recordingDiagnosisProvider{}
	runner := NewRunnerWithProcessor(Options{
		InputPath:         testInputFile(t, "host_iostat.dat"),
		EnableAI:          true,
		DiagnosisProvider: provider,
		OutputFormat:      "report",
	}, processorSpy)

	if err := runner.Run(); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if processorSpy.aiProvider == nil {
		t.Fatalf("runner should inject the configured diagnosis provider")
	}
}

func testInputFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("test"), 0o644); err != nil {
		t.Fatalf("write test input: %v", err)
	}
	return path
}
