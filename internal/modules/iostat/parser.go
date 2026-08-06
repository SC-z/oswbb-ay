package iostat

import (
	"errors"
	"fmt"
	legacyiostat "oswbb-analyse/pkg/iostat"
	"sort"
)

// Parser adapts the existing pkg/iostat parser to the new module boundary.
type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// ParseFiles parses one or more already-classified iostat files.
// It does not diagnose, print, or build reports; partial parse errors are
// returned in ParsedData when at least one file produced valid snapshots.
func (p *Parser) ParseFiles(files []string) (*ParsedData, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("iostat 文件列表不能为空")
	}

	legacyParser := &legacyiostat.IOStatParser{}
	var allData []legacyiostat.IOStatData
	var parseErrs []error
	firstHeader := ""

	for _, filename := range files {
		log, err := legacyParser.ParseFile(filename)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("解析 iostat 文件失败 %s: %w", filename, err))
			continue
		}
		if len(log.Data) == 0 {
			parseErrs = append(parseErrs, fmt.Errorf("解析 iostat 文件失败 %s: 没有有效的 iostat 数据", filename))
			continue
		}
		if firstHeader == "" {
			firstHeader = log.Header
		}
		allData = append(allData, log.Data...)
	}

	if len(allData) == 0 {
		return nil, errors.Join(parseErrs...)
	}

	sort.Slice(allData, func(i, j int) bool {
		return allData[i].Timestamp.Before(allData[j].Timestamp)
	})

	header := firstHeader
	if len(files) > 1 {
		header = fmt.Sprintf("合并了 %d 个文件", len(files))
	}

	return &ParsedData{
		Log: &legacyiostat.IOStatLog{
			Header: header,
			Data:   allData,
		},
		Files:       append([]string(nil), files...),
		ParseErrors: parseErrs,
	}, nil
}
