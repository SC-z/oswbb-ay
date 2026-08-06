package main

import (
	"flag"
	"fmt"
	"os"
	"oswbb-analyse/internal/app"
	"oswbb-analyse/internal/cli"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/logging"
	"oswbb-analyse/pkg/localai"
	"oswbb-analyse/pkg/processor"
	"time"
)

func main() {
	inputFile := flag.String("f", "", "OSWbb日志文件路径或目录 (支持iostat、meminfo和top)")
	startTimeStr := flag.String("start", "", "开始时间 (格式: 2006-01-02 15:04:05)")
	endTimeStr := flag.String("end", "", "结束时间 (格式: 2006-01-02 15:04:05)")
	singleMode := flag.Bool("s", false, "单文件模式: 每个文件独立解析报告 (默认: 同类文件合并分析)")
	outputFormat := flag.String("o", "ml", "输出格式: report, csv, json, ml, html；未显式指定时默认 ml")
	aiModelPath := flag.String("ai-model-path", "", "本地 GGUF 模型路径，覆盖默认模型查找规则")
	aiRuntimePath := flag.String("ai-runtime-path", "", "本地 llama.cpp runtime 路径，覆盖默认 llama-cli 查找规则")
	aiDebug := flag.Bool("ai-debug", false, "打印本地 AI 调试信息，包括输入给模型的数据、prompt 和 GPU/CPU runtime 决策")
	aiTimeout := flag.String("ai-timeout", "", "本地 AI 单次 runtime 调用超时时间，例如 60s、180s、5m；为空使用默认值")
	configPath := flag.String("config", "", "可选 TOML 配置文件路径，用于覆盖分析阈值")
	flag.Bool("ai-local", false, "兼容参数: AI 专用入口始终启用本地 AI")
	flag.Parse()

	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fatal(err)
	}
	effectiveOutputFormat, err := resolveEffectiveOutputFormat(*outputFormat, isFlagPassed("o"), cfg.AI.DefaultOutputFormat, flag.Args())
	if err != nil {
		fatal(err)
	}
	effectiveAITimeout, err := resolveAITimeout(*aiTimeout, isFlagPassed("ai-timeout"), cfg.AI.TimeoutSeconds)
	if err != nil {
		fatal(err)
	}

	if *inputFile == "" {
		fatal("请使用 -f 参数指定OSWbb日志文件路径或目录")
	}

	// AI 版复用 app.Runner 的主流程边界，但必须注入 localai service。
	// 普通版入口不能链接 localai，这里保持两个入口的依赖差异清晰可测。
	runner := app.NewRunnerWithProcessor(app.Options{
		InputPath:    resolveEffectiveInputPath(*inputFile, flag.Args()),
		StartTime:    *startTimeStr,
		EndTime:      *endTimeStr,
		SingleMode:   *singleMode,
		OutputFormat: effectiveOutputFormat,
		EnableAI:     true,
		Config:       cfg,
		AIConfig: processor.AIConfig{
			Debug:       *aiDebug,
			ModelPath:   *aiModelPath,
			RuntimePath: *aiRuntimePath,
			Timeout:     effectiveAITimeout,
		},
		Location:          time.FixedZone("CST", 8*3600),
		DiagnosisProvider: localai.NewService(nil),
	}, processor.NewFileProcessorWithConfig(cfg))
	if err := runner.Run(); err != nil {
		fatal(err)
	}
}

func fatal(v interface{}) {
	logging.Default().Errorf("%v", v)
	os.Exit(1)
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func resolveEffectiveOutputFormat(requested string, outputExplicit bool, configDefault string, trailingArgs []string) (string, error) {
	if trailingOutputFormat, found, err := cli.TrailingOutputFormat(trailingArgs); err != nil || found {
		return trailingOutputFormat, err
	}
	if !outputExplicit {
		return configDefault, nil
	}
	return requested, nil
}

func resolveEffectiveInputPath(inputPath string, trailingArgs []string) string {
	if expandedDir, ok := cli.ExpandedInputDirectory(inputPath, trailingArgs); ok {
		return expandedDir
	}
	return inputPath
}

func resolveAITimeout(raw string, explicit bool, configSeconds int) (time.Duration, error) {
	if !explicit {
		if configSeconds <= 0 {
			return 0, nil
		}
		return time.Duration(configSeconds) * time.Second, nil
	}
	if raw == "" {
		return 0, nil
	}
	timeout, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("--ai-timeout 格式无效: %q，请使用 60s、180s 或 5m 这类 Go duration 格式", raw)
	}
	if timeout <= 0 {
		return 0, fmt.Errorf("--ai-timeout 必须大于 0")
	}
	return timeout, nil
}
