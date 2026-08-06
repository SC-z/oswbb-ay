package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAIEntrypointDefaultsToMLWhenOutputNotExplicit(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("report", false, "ml", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "ml" {
		t.Fatalf("expected AI entrypoint without explicit -o to default to ml, got %q", got)
	}
}

func TestAIEntrypointKeepsExplicitOutput(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("json", true, "ml", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "json" {
		t.Fatalf("expected AI entrypoint explicit output format to be preserved, got %q", got)
	}
}

func TestAIEntrypointHonorsOutputFlagAfterExpandedInputArgs(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("ml", false, "ml", []string{
		"./rdsmaster1_iostat_26.04.20.2300.dat",
		"./rdsmaster1_iostat_26.04.21.0000.dat",
		"-o=html",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "html" {
		t.Fatalf("expected trailing -o=html to override AI default ml, got %q", got)
	}
}

func TestAIEntrypointConfigDefaultAndExplicitOutputPrecedence(t *testing.T) {
	got, err := resolveEffectiveOutputFormat("ml", false, "json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "json" {
		t.Fatalf("config AI output default should apply when -o is not explicit, got %q", got)
	}

	got, err = resolveEffectiveOutputFormat("html", true, "json", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "html" {
		t.Fatalf("explicit -o should override config AI output default, got %q", got)
	}
}

func TestAIEntrypointNormalizesExpandedInputArgsToDirectory(t *testing.T) {
	got := resolveEffectiveInputPath(
		"./iostat_rdsmaster1_20260618144603_000000000.html",
		[]string{
			"./rdsmaster1_iostat_26.04.20.2300.dat",
			"./rdsmaster1_iostat_26.04.21.0000.dat",
			"-o=html",
		},
	)
	if got != "." {
		t.Fatalf("expected expanded input args to normalize to current directory, got %q", got)
	}
}

func TestAIEntrypointHelpShowsMLAsDefaultOutput(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--help")
	cmd.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run --help failed: %v\n%s", err, output)
	}

	text := string(output)
	if !strings.Contains(text, `-o string`) || !strings.Contains(text, `(default "ml")`) {
		t.Fatalf("AI help 应把 -o 默认值显示为 ml:\n%s", text)
	}
	if strings.Contains(text, `(default "report")`) {
		t.Fatalf("AI help 不应显示与实际行为冲突的 report 默认值:\n%s", text)
	}
}

func TestAIEntrypointAcceptsAILocalCompatibilityFlag(t *testing.T) {
	cmd := exec.Command("go", "run", ".", "--ai-local", "--help")
	cmd.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("AI 专用入口应兼容 --ai-local 参数: %v\n%s", err, output)
	}

	if !strings.Contains(string(output), "兼容参数") {
		t.Fatalf("AI help 应说明 --ai-local 是兼容参数:\n%s", output)
	}
}

func TestResolveAITimeoutAllowsEmptyAndDuration(t *testing.T) {
	got, err := resolveAITimeout("", false, 0)
	if err != nil {
		t.Fatalf("空 timeout 应使用默认值而不是报错: %v", err)
	}
	if got != 0 {
		t.Fatalf("空 timeout 应返回 0 表示使用 localai 默认值, got=%s", got)
	}

	got, err = resolveAITimeout("180s", true, 0)
	if err != nil {
		t.Fatalf("合法 timeout 不应报错: %v", err)
	}
	if got != 180*time.Second {
		t.Fatalf("timeout 解析错误, got=%s", got)
	}
}

func TestResolveAITimeoutUsesConfigWhenNotExplicit(t *testing.T) {
	got, err := resolveAITimeout("", false, 120)
	if err != nil {
		t.Fatalf("config timeout should parse: %v", err)
	}
	if got != 120*time.Second {
		t.Fatalf("config timeout should be used when flag is not explicit, got=%s", got)
	}

	got, err = resolveAITimeout("180s", true, 120)
	if err != nil {
		t.Fatalf("explicit timeout should parse: %v", err)
	}
	if got != 180*time.Second {
		t.Fatalf("explicit timeout should override config, got=%s", got)
	}
}

func TestResolveAITimeoutRejectsInvalidDuration(t *testing.T) {
	if _, err := resolveAITimeout("slow", true, 0); err == nil {
		t.Fatalf("非法 timeout 应返回错误")
	}
}

func TestAIEntrypointLinksLocalAI(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", ".")
	cmd.Env = append(os.Environ(), "GOCACHE="+t.TempDir())
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list failed: %v\n%s", err, output)
	}

	for _, dep := range strings.Fields(string(output)) {
		if dep == "oswbb-analyse/pkg/localai" {
			return
		}
	}
	t.Fatalf("AI 专用入口必须链接 localai，deps 未包含 oswbb-analyse/pkg/localai:\n%s", output)
}
