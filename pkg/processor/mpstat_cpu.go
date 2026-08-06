package processor

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
)

var mpstatCPUCountRe = regexp.MustCompile(`\(([0-9]+)\s+CPU\)`)

func parseMPStatCPUCountFile(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := mpstatCPUCountRe.FindStringSubmatch(scanner.Text())
		if len(match) != 2 {
			continue
		}
		count, err := strconv.Atoi(match[1])
		if err != nil || count <= 0 {
			return 0, fmt.Errorf("无效 CPU 核数 %q", match[1])
		}
		return count, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("未找到 CPU 核数")
}

func parseMPStatCPUCountFiles(filenames []string) (int, []error) {
	var errs []error
	for _, filename := range filenames {
		count, err := parseMPStatCPUCountFile(filename)
		if err != nil {
			errs = append(errs, fmt.Errorf("解析 mpstat CPU 核数失败 %s: %v", filename, err))
			continue
		}
		return count, errs
	}
	return 0, errs
}
