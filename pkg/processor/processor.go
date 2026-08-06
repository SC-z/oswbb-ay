package processor

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"oswbb-analyse/internal/config"
	"oswbb-analyse/internal/core"
	"oswbb-analyse/internal/logging"
	internaloutput "oswbb-analyse/internal/output"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileProcessor 文件处理器
type FileProcessor struct {
	aiService    AIDiagnoser
	cfg          config.Config
	reportRunner ModuleReportRunner
	outputSink   internaloutput.OutputSink
}

// ProcessPath 处理路径 (文件或目录)
func (fp *FileProcessor) ProcessPath(inputPath, startTimeStr, endTimeStr string, singleMode bool, outputFormat string, cst *time.Location, aiConfig AIConfig) error {
	// 检查是文件还是目录
	fileInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("无法访问指定路径: %v", err)
	}

	if fileInfo.IsDir() {
		// 处理目录
		return fp.ProcessDirectory(inputPath, startTimeStr, endTimeStr, singleMode, outputFormat, cst, aiConfig)
	} else {
		// 处理单个文件
		return fp.ProcessSingleFile(inputPath, startTimeStr, endTimeStr, outputFormat, cst, aiConfig)
	}
}

// extractHostname 从文件路径中提取主机名
func extractHostname(filePath string) string {
	filename := filepath.Base(filePath)
	parts := strings.Split(filename, "_")
	if len(parts) >= 2 {
		return parts[0]
	}
	return ""
}

// ProcessSingleFile 处理单个文件
func (fp *FileProcessor) ProcessSingleFile(filename, startTimeStr, endTimeStr, outputFormat string, cst *time.Location, aiConfig AIConfig) error {
	bundle, err := parseSingleBundle(filename)
	if err != nil {
		return err
	}
	return fp.executeBundle(bundle, startTimeStr, endTimeStr, outputFormat, cst, aiConfig)
}

// ProcessDirectory 处理目录中的所有相关文件
func (fp *FileProcessor) ProcessDirectory(dirPath, startTimeStr, endTimeStr string, singleMode bool, outputFormat string, cst *time.Location, aiConfig AIConfig) error {
	logging.Default().Infof("扫描目录: %s", dirPath)

	iostatFiles, meminfoFiles, topFiles, mpstatFiles, gzFiles, err := scanDirectory(dirPath)
	if err != nil {
		return fmt.Errorf("扫描目录失败: %v", err)
	}

	// 报告发现的文件
	logging.Default().Infof("发现 %d 个iostat文件", len(iostatFiles))
	logging.Default().Infof("发现 %d 个meminfo文件", len(meminfoFiles))
	logging.Default().Infof("发现 %d 个top文件", len(topFiles))
	logging.Default().Infof("发现 %d 个mpstat文件(用于CPU核数辅助判断)", len(mpstatFiles))

	if len(gzFiles) > 0 {
		decompressedFiles, cleanup, err := decompressGzFiles(gzFiles)
		defer cleanup()
		if err != nil {
			logging.Default().Warnf("解压过程出现警告: %v", err)
		}

		decompressedIOStat, decompressedMemInfo, decompressedTop, decompressedMPStat := classifyLogFiles(decompressedFiles)
		iostatFiles = append(iostatFiles, decompressedIOStat...)
		meminfoFiles = append(meminfoFiles, decompressedMemInfo...)
		topFiles = append(topFiles, decompressedTop...)
		mpstatFiles = append(mpstatFiles, decompressedMPStat...)
		logging.Default().Infof("临时解压完成，继续分析压缩文件内容...")
	}

	if len(iostatFiles) == 0 && len(meminfoFiles) == 0 && len(topFiles) == 0 {
		logging.Default().Infof("目录中未找到包含 'iostat', 'meminfo' 或 'top' 的文件")
		return nil
	}

	if singleMode {
		return fp.processSingleFiles(iostatFiles, meminfoFiles, topFiles, startTimeStr, endTimeStr, outputFormat, cst, aiConfig)
	}

	return fp.processMergedFiles(iostatFiles, meminfoFiles, topFiles, mpstatFiles, startTimeStr, endTimeStr, outputFormat, cst, aiConfig)
}

// scanDirectory 扫描目录并分类文件
func scanDirectory(dirPath string) (iostatFiles, meminfoFiles, topFiles, mpstatFiles, gzFiles []string, err error) {
	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		if strings.HasPrefix(info.Name(), ".") {
			return nil
		}

		fileName := strings.ToLower(info.Name())

		if strings.HasSuffix(fileName, ".gz") {
			gzFiles = append(gzFiles, path)
			return nil
		}

		switch classifyLogFile(path) {
		case "iostat":
			iostatFiles = append(iostatFiles, path)
		case "meminfo":
			meminfoFiles = append(meminfoFiles, path)
		case "top":
			topFiles = append(topFiles, path)
		case "mpstat":
			mpstatFiles = append(mpstatFiles, path)
		}

		return nil
	})
	return
}

func classifyLogFiles(files []string) (iostatFiles, meminfoFiles, topFiles, mpstatFiles []string) {
	for _, file := range files {
		switch classifyLogFile(file) {
		case "iostat":
			iostatFiles = append(iostatFiles, file)
		case "meminfo":
			meminfoFiles = append(meminfoFiles, file)
		case "top":
			topFiles = append(topFiles, file)
		case "mpstat":
			mpstatFiles = append(mpstatFiles, file)
		}
	}
	return iostatFiles, meminfoFiles, topFiles, mpstatFiles
}

func classifyLogFile(path string) string {
	if fileType, ok := core.DetectFileType(path); ok {
		return string(fileType)
	}
	fileName := strings.ToLower(filepath.Base(path))
	// Directory scans should only classify raw OSWbb samples. Generated outputs
	// such as iostat_*.html or iostat_*.csv often sit beside samples during
	// manual use and must not be parsed as input logs.
	if !strings.HasSuffix(fileName, ".dat") {
		return ""
	}
	if strings.Contains(fileName, "mpstat") {
		return "mpstat"
	}
	return ""
}

// decompressGzFiles 解压到临时目录并保留原始 .gz 归档。
func decompressGzFiles(gzFiles []string) ([]string, func(), error) {
	logging.Default().Infof("发现 %d 个压缩文件(.gz)，正在临时解压...", len(gzFiles))
	if len(gzFiles) == 0 {
		return nil, func() {}, nil
	}

	tempDir, err := os.MkdirTemp("", "oswbb-analyse-gz-*")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
	}

	var decompressed []string
	var failures []string
	for i, gzFile := range gzFiles {
		logging.Default().Infof("临时解压: %s", gzFile)
		outputFile := filepath.Join(tempDir, fmt.Sprintf("%03d_%s", i, strings.TrimSuffix(filepath.Base(gzFile), ".gz")))
		if err := decompressGzFile(gzFile, outputFile); err != nil {
			logging.Default().Warnf("解压失败 %s: %v", gzFile, err)
			failures = append(failures, fmt.Sprintf("%s: %v", gzFile, err))
			continue
		}
		decompressed = append(decompressed, outputFile)
	}

	if len(failures) > 0 {
		return decompressed, cleanup, fmt.Errorf("%s", strings.Join(failures, "; "))
	}
	return decompressed, cleanup, nil
}

func decompressGzFile(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()

	reader, err := gzip.NewReader(input)
	if err != nil {
		return err
	}
	defer reader.Close()

	output, err := os.Create(target)
	if err != nil {
		return err
	}
	defer output.Close()

	_, err = io.Copy(output, reader)
	return err
}

// processSingleFiles 单文件模式处理
func (fp *FileProcessor) processSingleFiles(iostatFiles, meminfoFiles, topFiles []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location, aiConfig AIConfig) error {
	logging.Default().Infof("单文件模式: 每个文件独立分析")

	var failures []string
	processFiles := func(files []string, fileType string) {
		for i, file := range files {
			logging.Default().Infof("%s", strings.Repeat("=", 80))
			logging.Default().Infof("正在分析%s文件 [%d/%d]: %s", fileType, i+1, len(files), file)
			logging.Default().Infof("%s", strings.Repeat("=", 80))
			if err := fp.ProcessSingleFile(file, startTimeStr, endTimeStr, outputFormat, cst, aiConfig); err != nil {
				logging.Default().Errorf("分析失败: %v", err)
				failures = append(failures, fmt.Sprintf("%s: %v", file, err))
			}
		}
	}

	processFiles(iostatFiles, "iostat")
	processFiles(meminfoFiles, "meminfo")
	processFiles(topFiles, "top")
	if len(failures) > 0 {
		return fmt.Errorf("有 %d 个文件分析失败: %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

// processMergedFiles 合并模式处理
func (fp *FileProcessor) processMergedFiles(iostatFiles, meminfoFiles, topFiles, mpstatFiles []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location, aiConfig AIConfig) error {
	logging.Default().Infof("合并模式: 按主机名分组统一分析")

	hostFiles := groupFilesByHost(iostatFiles, meminfoFiles, topFiles, mpstatFiles)
	hostnames := make([]string, 0, len(hostFiles))
	for hostname := range hostFiles {
		hostnames = append(hostnames, hostname)
	}
	sort.Strings(hostnames)

	var failures []string
	for _, hostname := range hostnames {
		fileTypes := hostFiles[hostname]
		logging.Default().Infof("%s", strings.Repeat("=", 80))
		logging.Default().Infof("主机: %s", hostname)
		logging.Default().Infof("%s", strings.Repeat("=", 80))
		bundle, err := parseMergedBundle(hostname, fileTypes)
		if err != nil {
			logging.Default().Errorf("主机 %s 分析失败: %v", hostname, err)
			failures = append(failures, fmt.Sprintf("%s: %v", hostname, err))
			continue
		}
		if err := fp.executeBundle(bundle, startTimeStr, endTimeStr, outputFormat, cst, aiConfig); err != nil {
			logging.Default().Errorf("主机 %s 分析失败: %v", hostname, err)
			failures = append(failures, fmt.Sprintf("%s: %v", hostname, err))
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("有 %d 个主机分析失败: %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

// groupFilesByHost 按主机名分组文件
func groupFilesByHost(iostatFiles, meminfoFiles, topFiles, mpstatFiles []string) map[string]map[string][]string {
	hostFiles := make(map[string]map[string][]string)

	addFile := func(files []string, fileType string) {
		for _, file := range files {
			hostname := extractHostname(file)
			if hostname != "" {
				if hostFiles[hostname] == nil {
					hostFiles[hostname] = make(map[string][]string)
				}
				hostFiles[hostname][fileType] = append(hostFiles[hostname][fileType], file)
			}
		}
	}

	addFile(iostatFiles, "iostat")
	addFile(meminfoFiles, "meminfo")
	addFile(topFiles, "top")
	addFile(mpstatFiles, "mpstat")
	return hostFiles
}
