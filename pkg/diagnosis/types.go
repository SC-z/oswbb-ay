package diagnosis

type SignalLevel string

const (
	SignalLevelHard SignalLevel = "hard"
	SignalLevelSoft SignalLevel = "soft"
)

const (
	AIStatusDisabled = "disabled"
	AIStatusActive   = "active"
	AIStatusFallback = "fallback"
)

// Evidence 是提供给本地模型的结构化诊断证据。
type Evidence struct {
	ID            string             `json:"signal_id"`
	Source        string             `json:"source"`
	Level         SignalLevel        `json:"level"`
	Title         string             `json:"title"`
	Summary       string             `json:"summary"`
	Category      string             `json:"category,omitempty"`
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

// Context 是一次 AI 诊断请求的完整上下文。
type Context struct {
	Hostname  string     `json:"hostname,omitempty"`
	StartTime string     `json:"start_time,omitempty"`
	EndTime   string     `json:"end_time,omitempty"`
	Modules   []string   `json:"modules,omitempty"`
	Notes     []string   `json:"notes,omitempty"`
	Evidence  []Evidence `json:"evidence"`
}

// Incident 是模型返回的高置信结论。
type Incident struct {
	Classification string   `json:"classification"`
	Severity       string   `json:"severity"`
	Confidence     float64  `json:"confidence"`
	EvidenceIDs    []string `json:"evidence_ids"`
	NextChecks     []string `json:"next_checks,omitempty"`
}

// AIResult 表示一次本地模型辅助诊断的最终状态。
type AIResult struct {
	Enabled        bool       `json:"enabled"`
	Status         string     `json:"status"`
	Model          string     `json:"model,omitempty"`
	RuntimePath    string     `json:"runtime_path,omitempty"`
	Summary        string     `json:"summary,omitempty"`
	Incidents      []Incident `json:"incidents,omitempty"`
	FallbackReason string     `json:"fallback_reason,omitempty"`
	EvidenceCount  int        `json:"evidence_count,omitempty"`
}

func DisabledResult() AIResult {
	return AIResult{
		Enabled: false,
		Status:  AIStatusDisabled,
	}
}

func FallbackResult(model, reason string, evidenceCount int) AIResult {
	return AIResult{
		Enabled:        true,
		Status:         AIStatusFallback,
		Model:          model,
		FallbackReason: reason,
		EvidenceCount:  evidenceCount,
	}
}

func ActiveResult(model, runtimePath, summary string, incidents []Incident, evidenceCount int) AIResult {
	return AIResult{
		Enabled:       true,
		Status:        AIStatusActive,
		Model:         model,
		RuntimePath:   runtimePath,
		Summary:       summary,
		Incidents:     incidents,
		EvidenceCount: evidenceCount,
	}
}

func (c Context) EvidenceIDs() map[string]struct{} {
	ids := make(map[string]struct{}, len(c.Evidence))
	for _, evidence := range c.Evidence {
		ids[evidence.ID] = struct{}{}
	}
	return ids
}
