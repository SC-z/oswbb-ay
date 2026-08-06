package report

type Finding struct {
	Severity string `json:"severity,omitempty"`
	Nature   string `json:"nature,omitempty"`
	Title    string `json:"title,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Evidence string `json:"evidence,omitempty"`
}
