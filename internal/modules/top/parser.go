package top

import (
	"errors"
	"fmt"
	legacytop "oswbb-analyse/pkg/top"
	"sort"
)

// Parser adapts pkg/top parsing behind the internal module boundary.
type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// ParseFiles parses and merges already-classified top files.
// It deliberately avoids diagnosis and report generation.
func (p *Parser) ParseFiles(files []string) (*ParsedData, error) {
	if len(files) == 0 {
		return nil, fmt.Errorf("top 文件列表不能为空")
	}

	legacyParser := legacytop.NewTopParser()
	var allData []legacytop.TopSnapshot
	var parseErrs []error

	for _, filename := range files {
		log, err := legacyParser.ParseFile(filename)
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("解析 top 文件失败 %s: %w", filename, err))
			continue
		}
		if len(log.Snapshots) == 0 {
			parseErrs = append(parseErrs, fmt.Errorf("解析 top 文件失败 %s: 没有有效的 top 数据", filename))
			continue
		}
		allData = append(allData, log.Snapshots...)
	}

	if len(allData) == 0 {
		return nil, errors.Join(parseErrs...)
	}

	sort.Slice(allData, func(i, j int) bool {
		return allData[i].Timestamp.Before(allData[j].Timestamp)
	})

	return &ParsedData{
		Log: &legacytop.TopLog{
			Snapshots: allData,
		},
		Files:       append([]string(nil), files...),
		ParseErrors: parseErrs,
	}, nil
}
