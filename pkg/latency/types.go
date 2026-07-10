package latency

import "time"

const (
	StatusOK          = "ok"
	StatusTimeout     = "timeout"
	StatusPingError   = "ping_error"
	StatusConfigError = "config_error"
)

type Sample struct {
	Timestamp time.Time
	Source    string
	Target    string
	Address   string
	Size      int
	Status    string
	RTTMS     float64
}

type Log struct {
	Samples []Sample
}

func (l *Log) GetTimeRange() (time.Time, time.Time) {
	if l == nil || len(l.Samples) == 0 {
		return time.Time{}, time.Time{}
	}
	start := l.Samples[0].Timestamp
	end := start
	for _, sample := range l.Samples[1:] {
		if sample.Timestamp.Before(start) {
			start = sample.Timestamp
		}
		if sample.Timestamp.After(end) {
			end = sample.Timestamp
		}
	}
	return start, end
}
