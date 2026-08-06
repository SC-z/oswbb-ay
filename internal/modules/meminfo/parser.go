package meminfo

import (
	"errors"
	"fmt"
	legacymeminfo "oswbb-analyse/pkg/meminfo"
	"sort"
)

// Parser adapts pkg/meminfo parsing behind the internal module boundary.
type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// ParseFiles parses and merges already-classified meminfo files.
// It does not diagnose or build reports; those stages are handled separately.
func (p *Parser) ParseFiles(files []string) (*ParsedData, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("meminfo 文件列表不能为空")
	}

	legacyParser := &legacymeminfo.MemInfoParser{}
	var allData []legacymeminfo.MemStatData
	var parseErrs []error

	for _, filename := range files {
		log, err := legacyParser.ParseFile(filename)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("解析 meminfo 文件失败 %s: %w", filename, err))
			continue
		}
		if len(log.Data) == 0 {
			parseErrs = append(parseErrs, fmt.Errorf("解析 meminfo 文件失败 %s: 没有有效的 meminfo 数据", filename))
			continue
		}
		allData = append(allData, log.Data...)
	}

	if len(allData) == 0 {
		return nil, errors.Join(parseErrs...)
	}

	sort.Slice(allData, func(i, j int) bool {
		return allData[i].Timestamp.Before(allData[j].Timestamp)
	})

	return &ParsedData{
		Log: &legacymeminfo.MemInfoLog{
			Data: allData,
		},
		Files:       append([]string(nil), files...),
		ParseErrors: parseErrs,
	}, nil
}
