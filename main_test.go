package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRuleEntrypointKeepsDefaultReportOutput(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("report", false, "report", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "report" {
		t.Fatalf("expected rule entrypoint default output to remain report, got %q", got)
	}
}

func TestRuleEntrypointKeepsMLAsCSVExportMode(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("ml", true, "report", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ml" {
		t.Fatalf("expected rule entrypoint to preserve ml export mode, got %q", got)
	}
}

func TestRuleEntrypointHonorsOutputFlagAfterExpandedInputArgs(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("report", false, "report", []string{
		"./rdsmaster1_iostat_26.04.20.2300.dat",
		"./rdsmaster1_iostat_26.04.21.0000.dat",
		"-o",
		"html",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "html" {
		t.Fatalf("expected trailing -o html to override default report, got %q", got)
	}
}

func TestRuleEntrypointRejectsTrailingOutputFlagWithoutValue(t *testing.T) {
	if _, err := resolveEffectiveOutputFormat("report", false, "report", []string{"./file.dat", "-o"}); err == nil {
		t.Fatalf("trailing -o without value should fail")
	}
}

func TestRuleEntrypointConfigDefaultAndExplicitOutputPrecedence(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("report", false, "json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "json" {
		t.Fatalf("config default should apply when -o is not explicit, got %q", got)
	}

	got, err = resolveEffectiveOutputFormat("csv", true, "json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "csv" {
		t.Fatalf("explicit -o should override config default, got %q", got)
	}
}

func TestRuleEntrypointNormalizesExpandedInputArgsToDirectory(t *testing.T) {
	got := resolveEffectiveInputPath(
		"./iostat_rdsmaster1_20260618144603_000000000.html",
		[]string{
			"./rdsmaster1_iostat_26.04.20.2300.dat",
			"./rdsmaster1_iostat_26.04.21.0000.dat",
			"-o",
			"html",
		},
	)
	if got != "." {
		t.Fatalf("expected expanded input args to normalize to current directory, got %q", got)
	}
}

func TestRuleEntrypointHelpDoesNotExposeAIFlags(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	cmd.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run --help failed: %v\n%s", err, output)
	}

	text := string(output)
	if !strings.Contains(text, `-o string`) || !strings.Contains(text, `(default "report")`) {
		t.Fatalf("规则版 help 应显示 -o 默认值为 report:\n%s", text)
	}
	for _, forbidden := range []string{"ai-local", "ai-debug", "ai-model-path", "ai-runtime-path"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("规则版 help 不应暴露 AI 参数 %q:\n%s", forbidden, text)
		}
	}
}

func TestRuleEntrypointRejectsAIFlags(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--ai-local", "--help")
	cmd.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("规则版入口不应接受 --ai-local，输出:\n%s", output)
	}
	text := string(output)
	if !strings.Contains(text, "flag provided but not defined") ||
		!strings.Contains(text, "ai-local") {
		t.Fatalf("规则版入口拒绝 AI 参数时应给出未定义 flag 错误:\n%s", text)
	}
}

func TestRuleEntrypointDoesNotLinkLocalAI(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, output)
	}

	for _, dep := range strings.Fields(string(output)) {
		if dep == "oswbb-analyse/pkg/localai" {
			t.Fatalf("rule entrypoint must not link local AI package; deps included %s", dep)
		}
	}
}
