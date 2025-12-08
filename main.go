package main

import (
	"flag"
	"log"
	"oswbb-analyse/pkg/processor"
	"time"
)

func main() {
	// 定义命令行参数
	inputFile := flag.String("f", "", "OSWbb日志文件路径或目录 (支持iostat和meminfo)")
	startTimeStr := flag.String("start", "", "开始时间 (格式: 2006-01-02 15:04:05)")
	endTimeStr := flag.String("end", "", "结束时间 (格式: 2006-01-02 15:04:05)")
	singleMode := flag.Bool("s", false, "单文件模式: 每个文件独立解析报告 (默认: 同类文件合并分析)")
	outputFormat := flag.String("o", "report", "输出格式: report(默认报告), csv, json, ml")
	flag.Parse()

	if *inputFile == "" {
		log.Fatal("请使用 -f 参数指定OSWbb日志文件路径或目录")
	}

	// 设置查询时间范围
	cst := time.FixedZone("CST", 8*3600)

	// 创建文件处理器并处理路径
	fp := processor.NewFileProcessor()
	if err := fp.ProcessPath(*inputFile, *startTimeStr, *endTimeStr, *singleMode, *outputFormat, cst); err != nil {
		log.Fatal(err)
	}
}
