package output

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"oswbb-analyse/internal/report"
)

func (f CSVFormatter) Format(r *report.Report) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("report 不能为空")
	}
	table, err := f.selectTable(r.Tables)
	if err != nil {
		return nil, err
	}
	if table == nil {
		return []byte{}, nil
	}

	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	if len(table.Headers) > 0 {
		if err := writer.Write(table.Headers); err != nil {
			return nil, fmt.Errorf("写入CSV头部失败: %v", err)
		}
	}
	for _, row := range table.Rows {
		if err := writer.Write(row); err != nil {
			return nil, fmt.Errorf("写入CSV数据行失败: %v", err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return nil, fmt.Errorf("写入CSV数据失败: %v", err)
	}
	return buf.Bytes(), nil
}

func (f CSVFormatter) selectTable(tables []report.Table) (*report.Table, error) {
	if len(tables) == 0 {
		return nil, nil
	}
	if f.TableName != "" {
		for i := range tables {
			if tables[i].Title == f.TableName {
				return &tables[i], nil
			}
		}
		return nil, fmt.Errorf("未找到CSV表: %s", f.TableName)
	}
	if len(tables) > 1 {
		return nil, fmt.Errorf("report 包含多个表，必须指定 TableName")
	}
	return &tables[0], nil
}
