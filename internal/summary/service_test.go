package summary

import (
	"strings"
	"testing"
)

func TestServiceBuildEmptyInputDoesNotPanic(t *testing.T) {
	got, err := (Service{}).Build(Input{})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if got == nil {
		t.Fatalf("Build returned nil report")
	}
	if len(got.Sections) != 1 || !strings.Contains(got.Sections[0].Body, "未发现主机级风险信号") {
		t.Fatalf("empty host summary body = %+v", got.Sections)
	}
}

func TestServiceBuildRanksRiskBeforeCandidates(t *testing.T) {
	got, err := (Service{}).Build(Input{Findings: []Finding{
		{
			Severity: "high",
			Nature:   "candidate",
			RuleID:   "iostat-write-latency-nvme11n1",
			Title:    "nvme11n1 写延迟存在突增",
			Source:   "iostat",
			Target:   "nvme11n1",
		},
		{
			Severity: "medium",
			Nature:   "risk",
			RuleID:   "top-zombie",
			Title:    "存在僵尸进程",
			Source:   "top",
			Target:   "system",
		},
	}})
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	body := got.Sections[0].Body
	for _, want := range []string{
		"风险信号=1 候选线索=1",
		"关键风险/线索:",
		"1. [中][风险信号] 存在僵尸进程 (top/system)",
		"2. [高][候选线索] nvme11n1 写延迟存在突增 (iostat/nvme11n1)",
		"建议优先查看: top/system, iostat/nvme11n1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("host summary missing %q:\n%s", want, body)
		}
	}
}
