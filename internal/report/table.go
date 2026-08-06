package report

type Table struct {
	Title   string     `json:"title,omitempty"`
	Headers []string   `json:"headers,omitempty"`
	Rows    [][]string `json:"rows,omitempty"`
}
