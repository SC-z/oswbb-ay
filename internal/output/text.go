package output

import (
	"fmt"
	"oswbb-analyse/internal/report"
	"strings"
)

const (
	textReportWidth      = 80
	textReportInnerWidth = 78
	textReportLineWidth  = 76
)

type TextLine struct {
	Label string
	Value string
}

func (TextFormatter) Format(r *report.Report) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("report 不能为空")
	}

	var sb strings.Builder
	module := r.Module
	if module == "" {
		module = "report"
	}
	sb.WriteString(RenderTextReportHeader(module))

	if len(r.Summary) > 0 {
		lines := make([]TextLine, 0, len(r.Summary))
		for _, item := range r.Summary {
			lines = append(lines, TextLine{Label: item.Name, Value: item.Value})
		}
		sb.WriteString(RenderTextOverview("分析概览", lines))
	}

	findingsBeforeSections := r.Metadata["findings_position"] == "before_sections"
	if findingsBeforeSections {
		sb.WriteString(renderFindings(r.Findings))
	}

	for _, section := range r.Sections {
		if section.Title != "" {
			sb.WriteString(RenderTextSectionTitle(section.Title))
		}
		if section.Body != "" {
			sb.WriteString(section.Body)
			if !strings.HasSuffix(section.Body, "\n") {
				sb.WriteString("\n")
			}
		}
	}

	if !findingsBeforeSections {
		sb.WriteString(renderFindings(r.Findings))
	}
	for _, table := range r.Tables {
		if table.Title != "" {
			sb.WriteString(RenderTextSectionTitle(table.Title))
		}
		if len(table.Headers) > 0 {
			sb.WriteString(strings.Join(table.Headers, "\t") + "\n")
		}
		for _, row := range table.Rows {
			sb.WriteString(strings.Join(row, "\t") + "\n")
		}
	}

	for _, suggestion := range r.Suggestions {
		sb.WriteString(RenderTextSectionTitle(suggestion.Title))
		if suggestion.Detail != "" {
			sb.WriteString(suggestion.Detail)
			if !strings.HasSuffix(suggestion.Detail, "\n") {
				sb.WriteString("\n")
			}
		}
	}

	return []byte(sb.String()), nil
}

func RenderTextReportHeader(module string) string {
	var sb strings.Builder
	sb.WriteString("\n")
	sb.WriteString(strings.Repeat("=", textReportWidth) + "\n")
	sb.WriteString(centerText(fmt.Sprintf("OSWbb Analyse Report - %s", module), textReportWidth) + "\n")
	sb.WriteString(strings.Repeat("=", textReportWidth) + "\n\n")
	return sb.String()
}

func RenderTextOverview(title string, lines []TextLine) string {
	boxLines := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line.Label) == "" {
			boxLines = append(boxLines, line.Value)
			continue
		}
		boxLines = append(boxLines, fmt.Sprintf("%s: %s", line.Label, line.Value))
	}
	return RenderTextBox("📊 "+title, boxLines)
}

func RenderTextSectionTitle(title string) string {
	return "\n" + title + "\n"
}

func RenderTextBox(title string, lines []string) string {
	var sb strings.Builder
	if title != "" {
		sb.WriteString(title + "\n")
	}
	sb.WriteString("┌" + strings.Repeat("─", textReportInnerWidth) + "┐\n")
	for _, line := range lines {
		writeBoxLine(&sb, line)
	}
	sb.WriteString("└" + strings.Repeat("─", textReportInnerWidth) + "┘\n\n")
	return sb.String()
}

func renderFindings(items []report.Finding) string {
	var sb strings.Builder
	sb.WriteString(RenderTextSectionTitle("📌 规则诊断摘要"))
	sb.WriteString("=== 异常摘要 ===\n")

	lines := []string{}
	if len(items) == 0 {
		lines = append(lines, "未发现明显异常")
	} else {
		for index, item := range items {
			if index > 0 {
				lines = append(lines, "")
			}
			nature := item.Nature
			if nature == "" {
				nature = "风险信号"
			}
			lines = append(lines, fmt.Sprintf("- [%s][%s] %s", item.Severity, nature, item.Title))
			if item.Evidence != "" {
				lines = append(lines, "  "+item.Evidence)
			}
			if item.Detail != "" {
				lines = append(lines, "  "+item.Detail)
			}
		}
	}

	sb.WriteString(RenderTextBox("", lines))
	return sb.String()
}

func writeBoxLine(sb *strings.Builder, line string) {
	if line == "" {
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", textReportLineWidth, ""))
		return
	}
	for _, part := range wrapRunes(line, textReportLineWidth) {
		sb.WriteString(fmt.Sprintf("│ %-*s │\n", textReportLineWidth, part))
	}
}

func wrapRunes(text string, limit int) []string {
	if limit <= 0 {
		return []string{text}
	}
	runes := []rune(text)
	if len(runes) <= limit {
		return []string{text}
	}
	fields := strings.Fields(text)
	if len(fields) > 1 {
		prefix := leadingWhitespace(text)
		parts := []string{}
		current := prefix + fields[0]
		for _, field := range fields[1:] {
			candidate := current + " " + field
			if runeLen(candidate) <= limit {
				current = candidate
				continue
			}
			parts = append(parts, current)
			current = prefix + field
		}
		parts = append(parts, current)
		return splitOversizedParts(parts, limit)
	}

	parts := make([]string, 0, len(runes)/limit+1)
	for len(runes) > limit {
		parts = append(parts, string(runes[:limit]))
		runes = runes[limit:]
	}
	if len(runes) > 0 {
		parts = append(parts, string(runes))
	}
	return parts
}

func leadingWhitespace(text string) string {
	var builder strings.Builder
	for _, char := range text {
		if char != ' ' && char != '\t' {
			break
		}
		builder.WriteRune(char)
	}
	return builder.String()
}

func splitOversizedParts(parts []string, limit int) []string {
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if runeLen(part) <= limit {
			result = append(result, part)
			continue
		}
		result = append(result, wrapRunesHard(part, limit)...)
	}
	return result
}

func wrapRunesHard(text string, limit int) []string {
	runes := []rune(text)
	parts := make([]string, 0, len(runes)/limit+1)
	for len(runes) > limit {
		parts = append(parts, string(runes[:limit]))
		runes = runes[limit:]
	}
	if len(runes) > 0 {
		parts = append(parts, string(runes))
	}
	return parts
}

func runeLen(text string) int {
	return len([]rune(text))
}

func centerText(text string, width int) string {
	if width <= runeLen(text) {
		return text
	}
	left := (width - runeLen(text)) / 2
	return strings.Repeat(" ", left) + text
}
