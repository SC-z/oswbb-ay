package findings

type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

type FindingNature string

const (
	FindingNatureRisk      FindingNature = "risk"
	FindingNatureCandidate FindingNature = "candidate"
)

type Finding struct {
	RuleID        string             `json:"rule_id"`
	Source        string             `json:"source"`
	Category      string             `json:"category"`
	Severity      Severity           `json:"severity"`
	Nature        FindingNature      `json:"nature,omitempty"`
	Title         string             `json:"title"`
	Summary       string             `json:"summary"`
	Target        string             `json:"target,omitempty"`
	Metric        string             `json:"metric,omitempty"`
	Operator      string             `json:"operator,omitempty"`
	Threshold     float64            `json:"threshold,omitempty"`
	ObservedValue float64            `json:"observed_value,omitempty"`
	EvidenceRef   string             `json:"evidence_ref,omitempty"`
	Time          string             `json:"time,omitempty"`
	WindowStart   string             `json:"window_start,omitempty"`
	WindowEnd     string             `json:"window_end,omitempty"`
	Metrics       map[string]float64 `json:"metrics,omitempty"`
	Tags          []string           `json:"tags,omitempty"`
}

func InferFindingNature(item Finding) FindingNature {
	if item.RuleID == "top-process-high-cpu" {
		return FindingNatureCandidate
	}
	if item.RuleID == "top-process-d-state" && metricEquals(item.Metrics, "d_state_pressure_corroborated", 0) {
		return FindingNatureCandidate
	}
	if item.RuleID == "top-cpu-wait" && metricEquals(item.Metrics, "cpu_wait_corroborated", 0) {
		return FindingNatureCandidate
	}
	if item.RuleID == "top-cpu-steal" &&
		metricLessOrEqual(item.Metrics, "cpu_steal_soft_sample_count", 1) &&
		metricLessOrEqual(item.Metrics, "cpu_steal_hard_sample_count", 1) {
		return FindingNatureCandidate
	}
	if item.Category == "disk_latency" && metricEquals(item.Metrics, "latency_system_pressure", 0) {
		return FindingNatureCandidate
	}
	if item.Category == "disk_utilization" && metricEquals(item.Metrics, "util_corroborated", 0) {
		return FindingNatureCandidate
	}
	if item.RuleID == "meminfo-anon-growth" && metricEquals(item.Metrics, "anon_pressure_corroborated", 0) {
		return FindingNatureCandidate
	}
	if item.RuleID == "meminfo-available" &&
		metricEquals(item.Metrics, "mem_available_recovered", 1) &&
		metricLessOrEqual(item.Metrics, "mem_available_soft_sample_count", 1) {
		return FindingNatureCandidate
	}
	if item.RuleID == "meminfo-swap-usage" && metricEquals(item.Metrics, "swap_recovered", 1) {
		return FindingNatureCandidate
	}
	if item.RuleID == "meminfo-commit-pressure" && metricEquals(item.Metrics, "committed_recovered", 1) {
		return FindingNatureCandidate
	}
	if item.RuleID == "meminfo-slab" && metricEquals(item.Metrics, "slab_recovered", 1) {
		return FindingNatureCandidate
	}
	if item.RuleID == "meminfo-writeback-pressure" && metricEquals(item.Metrics, "writeback_recovered", 1) {
		return FindingNatureCandidate
	}
	return FindingNatureRisk
}

func applyFindingNature(items []Finding) {
	for i := range items {
		if items[i].Nature == "" {
			items[i].Nature = InferFindingNature(items[i])
		}
	}
}

func metricEquals(metrics map[string]float64, key string, want float64) bool {
	got, ok := metrics[key]
	return ok && got == want
}

func metricLessOrEqual(metrics map[string]float64, key string, want float64) bool {
	got, ok := metrics[key]
	return ok && got <= want
}
