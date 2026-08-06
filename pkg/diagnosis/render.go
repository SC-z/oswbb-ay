package diagnosis

import (
	"fmt"
	"strings"
)

func FormatResultText(result AIResult) string {
	var sb strings.Builder
	sb.WriteString("\n=== AI 辅助诊断 ===\n")
	switch result.Status {
	case AIStatusFallback:
		fmt.Fprintf(&sb, "AI 诊断未生效，已回退到规则分析：%s\n", result.FallbackReason)
	case AIStatusActive:
		if result.Summary != "" {
			fmt.Fprintf(&sb, "总结：%s\n", result.Summary)
		}
		if len(result.Incidents) == 0 {
			if result.Summary == "" {
				sb.WriteString("模型本次未补充新的高置信结论。\n")
			}
			return sb.String()
		}
		for index, incident := range result.Incidents {
			fmt.Fprintf(&sb, "%d. %s [%s, confidence=%.2f]\n", index+1, incident.Classification, incident.Severity, incident.Confidence)
			if len(incident.EvidenceIDs) > 0 {
				fmt.Fprintf(&sb, "   证据: %s\n", strings.Join(incident.EvidenceIDs, ", "))
			}
			if len(incident.NextChecks) > 0 {
				fmt.Fprintf(&sb, "   建议核查: %s\n", strings.Join(incident.NextChecks, "；"))
			}
		}
	default:
		sb.WriteString("AI 诊断已关闭。\n")
	}
	return sb.String()
}
