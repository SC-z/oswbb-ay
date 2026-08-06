package output

import (
	"encoding/json"
	"fmt"
	"oswbb-analyse/internal/report"
)

func (JSONFormatter) Format(r *report.Report) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("report 不能为空")
	}
	return json.MarshalIndent(r, "", "  ")
}
