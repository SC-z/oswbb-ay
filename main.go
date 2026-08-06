package main

import (
	"flag"
	"os"
	"oswbb-analyse/internal/app"
	"oswbb-analyse/internal/cli"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/logging"
)

func main() {
	// 普通版入口只保留 CLI 参数解析，主流程统一交给 internal/app。
	// 这样后续拆分 processor 时不会继续把业务编排塞回 main。
	inputFile := flag.String("f", "", "OSWbb日志文件路径或目录 (支持iostat、meminfo和top)")
	startTimeStr := flag.String("start", "", "开始时间 (格式: 2006-01-02 15:04:05)")
	endTimeStr := flag.String("end", "", "结束时间 (格式: 2006-01-02 15:04:05)")
	singleMode := flag.Bool("s", false, "单文件模式: 每个文件独立解析报告 (默认: 同类文件合并分析)")
	outputFormat := flag.String("o", "report", "输出格式: report(默认报告), csv, json, ml, html")
	configPath := flag.String("config", "", "可选 TOML 配置文件路径，用于覆盖分析阈值")
	flag.Parse()
	cfg, err := config.LoadFile(*configPath)
	if err != nil {
		fatal(err)
	}
	effectiveOutputFormat, err := resolveEffectiveOutputFormat(*outputFormat, isFlagPassed("o"), cfg.General.DefaultOutputFormat, flag.Args())
	if err != nil {
		fatal(err)
	}

	if *inputFile == "" {
		fatal("请使用 -f 参数指定OSWbb日志文件路径或目录")
	}

	// 当前阶段仍复用旧 processor，Runner 只是稳定未来应用层边界。
	runner := app.NewRunner(app.Options{
		InputPath:    resolveEffectiveInputPath(*inputFile, flag.Args()),
		StartTime:    *startTimeStr,
		EndTime:      *endTimeStr,
		SingleMode:   *singleMode,
		OutputFormat: effectiveOutputFormat,
		Config:       cfg,
	})
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
