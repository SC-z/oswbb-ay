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

	var iostatFiles []string
	var meminfoFiles []string
	var gzFiles []string

	// 扫描目录
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		fileName := strings.ToLower(info.Name())

		// 检查压缩文件
		if strings.HasSuffix(fileName, ".gz") {
			gzFiles = append(gzFiles, path)
			return nil
		}

		// 检查相关文件
		if strings.Contains(fileName, "iostat") {
			iostatFiles = append(iostatFiles, path)
		} else if strings.Contains(fileName, "meminfo") {
			meminfoFiles = append(meminfoFiles, path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("扫描目录失败: %v", err)
	}

	// 报告发现的文件
	fmt.Printf("发现 %d 个iostat文件\n", len(iostatFiles))
	fmt.Printf("发现 %d 个meminfo文件\n", len(meminfoFiles))

	if len(gzFiles) > 0 {
		fmt.Printf("\n发现 %d 个压缩文件(.gz)，正在尝试自动解压...\n", len(gzFiles))
		for _, gzFile := range gzFiles {
			fmt.Printf("解压: %s\n", gzFile)
			cmd := exec.Command("gzip", "-d", gzFile)
			if err := cmd.Run(); err != nil {
				fmt.Printf("解压失败 %s: %v\n", gzFile, err)
			}
		}

		// 清空列表重新扫描
		iostatFiles = []string{}
		meminfoFiles = []string{}
		gzFiles = []string{}

		fmt.Println("解压完成，重新扫描目录...")
		err = filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			fileName := strings.ToLower(info.Name())

			// 再次检查，如果还有gz文件则忽略
			if strings.HasSuffix(fileName, ".gz") {
				return nil
			}

			// 检查相关文件
			if strings.Contains(fileName, "iostat") {
				iostatFiles = append(iostatFiles, path)
			} else if strings.Contains(fileName, "meminfo") {
				meminfoFiles = append(meminfoFiles, path)
			}

			return nil
		})

		if err != nil {
			return fmt.Errorf("重新扫描目录失败: %v", err)
		}
	}

	if len(iostatFiles) == 0 && len(meminfoFiles) == 0 {
		fmt.Println("目录中未找到包含 'iostat' 或 'meminfo' 的文件")
		return nil
	}

	if singleMode {
		// 单文件模式: 每个文件独立分析
		fmt.Println("\n单文件模式: 每个文件独立分析")

		// 处理iostat文件
		for i, file := range iostatFiles {
			fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
			fmt.Printf("正在分析iostat文件 [%d/%d]: %s\n", i+1, len(iostatFiles), file)
			fmt.Printf(strings.Repeat("=", 80) + "\n")
			if err := AnalyzeIOStatFile(file, startTimeStr, endTimeStr, outputFormat, cst); err != nil {
				fmt.Printf("分析失败: %v\n", err)
			}
		}

		// 处理meminfo文件
		for i, file := range meminfoFiles {
			fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
			fmt.Printf("正在分析meminfo文件 [%d/%d]: %s\n", i+1, len(meminfoFiles), file)
			fmt.Printf(strings.Repeat("=", 80) + "\n")
			if err := AnalyzeMemInfoFile(file, startTimeStr, endTimeStr, outputFormat, cst); err != nil {
				fmt.Printf("分析失败: %v\n", err)
			}
		}
	} else {
		// 合并模式: 按主机名分组合并分析
		fmt.Println("\n合并模式: 按主机名分组统一分析")

		// 按主机名分组所有文件
		hostFiles := make(map[string]map[string][]string) // hostFiles[hostname][filetype] = []files

		// 处理iostat文件
		for _, file := range iostatFiles {
			hostname := extractHostname(file)
			if hostname != "" {
				if hostFiles[hostname] == nil {
					hostFiles[hostname] = make(map[string][]string)
				}
				hostFiles[hostname]["iostat"] = append(hostFiles[hostname]["iostat"], file)
			}
		}

		// 处理meminfo文件
		for _, file := range meminfoFiles {
			hostname := extractHostname(file)
			if hostname != "" {
				if hostFiles[hostname] == nil {
					hostFiles[hostname] = make(map[string][]string)
				}
				hostFiles[hostname]["meminfo"] = append(hostFiles[hostname]["meminfo"], file)
			}
		}

		// 按主机名分组分析
		for hostname, fileTypes := range hostFiles {
			fmt.Printf("\n" + strings.Repeat("=", 80) + "\n")
			fmt.Printf("主机: %s\n", hostname)
			fmt.Printf(strings.Repeat("=", 80) + "\n")

			// 分析该主机的iostat文件
			if iostatFiles, exists := fileTypes["iostat"]; exists && len(iostatFiles) > 0 {
				fmt.Printf("\n--- 分析 %s 主机的 %d 个iostat文件 ---\n", hostname, len(iostatFiles))
				if err := AnalyzeMergedIOStatFiles(iostatFiles, startTimeStr, endTimeStr, outputFormat, cst); err != nil {
					fmt.Printf("iostat分析失败: %v\n", err)
				}
			}

			// 分析该主机的meminfo文件
			if meminfoFiles, exists := fileTypes["meminfo"]; exists && len(meminfoFiles) > 0 {
				fmt.Printf("\n--- 分析 %s 主机的 %d 个meminfo文件 ---\n", hostname, len(meminfoFiles))
				if err := AnalyzeMergedMemInfoFiles(meminfoFiles, startTimeStr, endTimeStr, outputFormat, cst); err != nil {
					fmt.Printf("meminfo分析失败: %v\n", err)
				}
			}
		}
	}

	return nil
}
