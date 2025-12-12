package processor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// FileProcessor 文件处理器
type FileProcessor struct{}

// NewFileProcessor 创建文件处理器
func NewFileProcessor() *FileProcessor {
	return &FileProcessor{}
}

// ProcessPath 处理路径 (文件或目录)
func (fp *FileProcessor) ProcessPath(inputPath, startTimeStr, endTimeStr string, singleMode bool, outputFormat string, cst *time.Location) error {
	// 检查是文件还是目录
	fileInfo, err := os.Stat(inputPath)
	if err != nil {
		return fmt.Errorf("无法访问指定路径: %v", err)
	}

	if fileInfo.IsDir() {
		// 处理目录
		return fp.ProcessDirectory(inputPath, startTimeStr, endTimeStr, singleMode, outputFormat, cst)
	} else {
		// 处理单个文件
		return fp.ProcessSingleFile(inputPath, startTimeStr, endTimeStr, outputFormat, cst)
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
func (fp *FileProcessor) ProcessSingleFile(filename, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {
	// 根据文件名检测文件类型
	fileName := strings.ToLower(filename)
	isIOStat := strings.Contains(fileName, "iostat")
	isMemInfo := strings.Contains(fileName, "meminfo")

	if !isIOStat && !isMemInfo {
		return fmt.Errorf("无法识别文件类型，文件名应包含 'iostat' 或 'meminfo'")
	}

	if isIOStat {
		return AnalyzeIOStatFile(filename, startTimeStr, endTimeStr, outputFormat, cst)
	} else if isMemInfo {
		return AnalyzeMemInfoFile(filename, startTimeStr, endTimeStr, outputFormat, cst)
	}

	return nil
}

// ProcessDirectory 处理目录中的所有相关文件

func (fp *FileProcessor) ProcessDirectory(dirPath, startTimeStr, endTimeStr string, singleMode bool, outputFormat string, cst *time.Location) error {

	fmt.Printf("扫描目录: %s\n", dirPath)



	iostatFiles, meminfoFiles, gzFiles, err := scanDirectory(dirPath)

	if err != nil {

		return fmt.Errorf("扫描目录失败: %v", err)

	}



	// 报告发现的文件

	fmt.Printf("发现 %d 个iostat文件\n", len(iostatFiles))

	fmt.Printf("发现 %d 个meminfo文件\n", len(meminfoFiles))



	if len(gzFiles) > 0 {

		if err := decompressGzFiles(gzFiles); err != nil {

			fmt.Printf("解压过程出现警告: %v\n", err)

		}



		fmt.Println("解压完成，重新扫描目录...")

		iostatFiles, meminfoFiles, _, err = scanDirectory(dirPath)

		if err != nil {

			return fmt.Errorf("重新扫描目录失败: %v", err)

		}

	}



	if len(iostatFiles) == 0 && len(meminfoFiles) == 0 {

		fmt.Println("目录中未找到包含 'iostat' 或 'meminfo' 的文件")

		return nil

	}



	if singleMode {

		return processSingleFiles(iostatFiles, meminfoFiles, startTimeStr, endTimeStr, outputFormat, cst)

	}



	return processMergedFiles(iostatFiles, meminfoFiles, startTimeStr, endTimeStr, outputFormat, cst)

}



// scanDirectory 扫描目录并分类文件

func scanDirectory(dirPath string) (iostatFiles, meminfoFiles, gzFiles []string, err error) {

	err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {

		if err != nil {

			return err

		}



		if info.IsDir() {

			return nil

		}



		fileName := strings.ToLower(info.Name())



		if strings.HasSuffix(fileName, ".gz") {

			gzFiles = append(gzFiles, path)

			return nil

		}



		if strings.Contains(fileName, "iostat") {

			iostatFiles = append(iostatFiles, path)

		} else if strings.Contains(fileName, "meminfo") {

			meminfoFiles = append(meminfoFiles, path)

		}



		return nil

	})

	return

}



// decompressGzFiles 批量解压文件

func decompressGzFiles(gzFiles []string) error {

	fmt.Printf("\n发现 %d 个压缩文件(.gz)，正在尝试自动解压...\n", len(gzFiles))

	for _, gzFile := range gzFiles {

		fmt.Printf("解压: %s\n", gzFile)

		cmd := exec.Command("gzip", "-d", gzFile)

		if err := cmd.Run(); err != nil {

			fmt.Printf("解压失败 %s: %v\n", gzFile, err)

		}

	}

	return nil

}



// processSingleFiles 单文件模式处理

func processSingleFiles(iostatFiles, meminfoFiles []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {

	fmt.Println("\n单文件模式: 每个文件独立分析")



	processFiles := func(files []string, fileType string, analyzeFunc func(string, string, string, string, *time.Location) error) {

		for i, file := range files {

			fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")

			fmt.Printf("正在分析%s文件 [%d/%d]: %s\n", fileType, i+1, len(files), file)

			fmt.Printf(strings.Repeat("=", 80) + "\n")

			if err := analyzeFunc(file, startTimeStr, endTimeStr, outputFormat, cst); err != nil {

				fmt.Printf("分析失败: %v\n", err)

			}

		}

	}



	processFiles(iostatFiles, "iostat", AnalyzeIOStatFile)

	processFiles(meminfoFiles, "meminfo", AnalyzeMemInfoFile)

	return nil

}



// processMergedFiles 合并模式处理

func processMergedFiles(iostatFiles, meminfoFiles []string, startTimeStr, endTimeStr, outputFormat string, cst *time.Location) error {

	fmt.Println("\n合并模式: 按主机名分组统一分析")



	hostFiles := groupFilesByHost(iostatFiles, meminfoFiles)



	for hostname, fileTypes := range hostFiles {

		fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")

		fmt.Printf("主机: %s\n", hostname)

		fmt.Printf(strings.Repeat("=", 80) + "\n")



		if files, exists := fileTypes["iostat"]; exists && len(files) > 0 {

			fmt.Printf("\n--- 分析 %s 主机的 %d 个iostat文件 ---\n", hostname, len(files))

			if err := AnalyzeMergedIOStatFiles(files, startTimeStr, endTimeStr, outputFormat, cst); err != nil {

				fmt.Printf("iostat分析失败: %v\n", err)

			}

		}



		if files, exists := fileTypes["meminfo"]; exists && len(files) > 0 {

			fmt.Printf("\n--- 分析 %s 主机的 %d 个meminfo文件 ---\n", hostname, len(files))

			if err := AnalyzeMergedMemInfoFiles(files, startTimeStr, endTimeStr, outputFormat, cst); err != nil {

				fmt.Printf("meminfo分析失败: %v\n", err)

			}

		}

	}

	return nil

}



// groupFilesByHost 按主机名分组文件

func groupFilesByHost(iostatFiles, meminfoFiles []string) map[string]map[string][]string {

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

	return hostFiles

}


