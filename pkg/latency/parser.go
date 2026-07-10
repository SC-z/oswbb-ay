package latency

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const recordPrefix = "OSWLATENCY|"

type Parser struct{}

func (p Parser) ParseFile(path string) (*Log, []error, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	return p.Parse(file)
}

func (Parser) Parse(r io.Reader) (*Log, []error, error) {
	log := &Log{}
	var warnings []error
	scanner := bufio.NewScanner(r)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := scanner.Text()
		if !strings.HasPrefix(line, recordPrefix) {
			continue
		}
		sample, err := parseRecord(strings.TrimPrefix(line, recordPrefix))
		if err != nil {
			warnings = append(warnings, fmt.Errorf("line %d: %w", lineNo, err))
			continue
		}
		log.Samples = append(log.Samples, sample)
	}
	if err := scanner.Err(); err != nil {
		return nil, warnings, err
	}
	return log, warnings, nil
}

func parseRecord(record string) (Sample, error) {
	fields := map[string]string{}
	for _, part := range strings.Split(record, "|") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || key == "" {
			return Sample{}, fmt.Errorf("invalid field %q", part)
		}
		fields[key] = value
	}
	for _, key := range []string{"timestamp", "source", "size", "status"} {
		if fields[key] == "" {
			return Sample{}, fmt.Errorf("missing %s", key)
		}
	}

	timestamp, err := parseTimestamp(fields["timestamp"])
	if err != nil {
		return Sample{}, fmt.Errorf("invalid timestamp: %w", err)
	}
	size, err := strconv.Atoi(fields["size"])
	if err != nil {
		return Sample{}, fmt.Errorf("invalid size: %w", err)
	}
	status := fields["status"]
	if status != StatusConfigError && (fields["target"] == "" || fields["address"] == "") {
		return Sample{}, fmt.Errorf("missing target or address")
	}
	if status == StatusConfigError {
		if size != 0 {
			return Sample{}, fmt.Errorf("config_error size must be 0")
		}
	} else if size != 56 && size != 8192 {
		return Sample{}, fmt.Errorf("unsupported size %d", size)
	}
	var rtt float64
	switch status {
	case StatusOK:
		rtt, err = strconv.ParseFloat(fields["rtt_ms"], 64)
		if err != nil || rtt < 0 {
			return Sample{}, fmt.Errorf("invalid rtt_ms %q", fields["rtt_ms"])
		}
	case StatusTimeout, StatusPingError, StatusConfigError:
		if fields["rtt_ms"] != "" {
			return Sample{}, fmt.Errorf("status %s must not contain rtt_ms", status)
		}
	default:
		return Sample{}, fmt.Errorf("unsupported status %q", status)
	}

	return Sample{
		Timestamp: timestamp,
		Source:    fields["source"],
		Target:    fields["target"],
		Address:   fields["address"],
		Size:      size,
		Status:    status,
		RTTMS:     rtt,
	}, nil
}

func parseTimestamp(value string) (time.Time, error) {
	var lastErr error
	for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339} {
		parsed, err := time.Parse(layout, value)
		if err == nil {
			return parsed, nil
		}
		lastErr = err
	}
	return time.Time{}, lastErr
}
