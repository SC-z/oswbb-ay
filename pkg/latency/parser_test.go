package latency

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParserKeepsValidSamplesAndReportsMalformedLines(t *testing.T) {
	input := strings.NewReader("raw ping output\n" +
		"OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=node1|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.183\n" +
		"OSWLATENCY|timestamp=bad|source=node1|target=node2|address=10.0.0.12|size=8192|status=timeout|rtt_ms=\n")

	log, warnings, err := (Parser{}).Parse(input)
	if err != nil {
		t.Fatalf("Parse 返回错误: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("warnings=%v, want 1 warning", warnings)
	}
	if len(log.Samples) != 1 {
		t.Fatalf("samples=%+v, want 1 sample", log.Samples)
	}

	sample := log.Samples[0]
	wantTime := time.Date(2026, 7, 10, 12, 0, 0, 0, time.FixedZone("+0800", 8*60*60))
	if !sample.Timestamp.Equal(wantTime) || sample.Source != "node1" || sample.Target != "node2" ||
		sample.Address != "10.0.0.12" || sample.Size != 56 || sample.Status != StatusOK || sample.RTTMS != 0.183 {
		t.Fatalf("sample=%+v", sample)
	}
}

func TestParserKeepsNonReplyStatuses(t *testing.T) {
	input := strings.NewReader(
		"OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=node1|target=node2|address=10.0.0.12|size=8192|status=timeout|rtt_ms=\n" +
			"OSWLATENCY|timestamp=2026-07-10T12:00:01+0800|source=node1|target=node2|address=10.0.0.12|size=56|status=ping_error|rtt_ms=\n" +
			"OSWLATENCY|timestamp=2026-07-10T12:00:02+0800|source=node1|target=|address=|size=0|status=config_error|rtt_ms=\n")

	log, warnings, err := (Parser{}).Parse(input)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("warnings=%v err=%v", warnings, err)
	}
	if len(log.Samples) != 3 {
		t.Fatalf("samples=%+v, want 3 samples", log.Samples)
	}
	want := []string{StatusTimeout, StatusPingError, StatusConfigError}
	for i, status := range want {
		if log.Samples[i].Status != status || log.Samples[i].RTTMS != 0 {
			t.Fatalf("sample[%d]=%+v", i, log.Samples[i])
		}
	}
}

func TestParserRejectsMissingFieldsAndUnsupportedSizes(t *testing.T) {
	input := strings.NewReader(
		"OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.2\n" +
			"OSWLATENCY|timestamp=2026-07-10T12:00:01+0800|source=node1|target=|address=10.0.0.12|size=8192|status=timeout|rtt_ms=\n" +
			"OSWLATENCY|timestamp=2026-07-10T12:00:02+0800|source=node1|target=node2|address=10.0.0.12|size=100|status=ok|rtt_ms=0.3\n")

	log, warnings, err := (Parser{}).Parse(input)
	if err != nil {
		t.Fatalf("Parse 返回错误: %v", err)
	}
	if len(log.Samples) != 0 || len(warnings) != 3 {
		t.Fatalf("samples=%+v warnings=%v", log.Samples, warnings)
	}
}

func TestParserAcceptsRFC3339Timestamp(t *testing.T) {
	input := strings.NewReader("OSWLATENCY|timestamp=2026-07-10T12:00:00+08:00|source=node1|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.2\n")

	log, warnings, err := (Parser{}).Parse(input)
	if err != nil || len(warnings) != 0 || len(log.Samples) != 1 {
		t.Fatalf("samples=%+v warnings=%v err=%v", log.Samples, warnings, err)
	}
}

func TestParseFileAndGetTimeRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node1_latency_26.07.10.1200.dat")
	content := "OSWLATENCY|timestamp=2026-07-10T12:00:02+0800|source=node1|target=node2|address=10.0.0.12|size=8192|status=timeout|rtt_ms=\n" +
		"OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=node1|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.2\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	log, warnings, err := (Parser{}).ParseFile(path)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("warnings=%v err=%v", warnings, err)
	}
	start, end := log.GetTimeRange()
	if got, want := start.Format(time.RFC3339), "2026-07-10T12:00:00+08:00"; got != want {
		t.Fatalf("start=%s, want %s", got, want)
	}
	if got, want := end.Format(time.RFC3339), "2026-07-10T12:00:02+08:00"; got != want {
		t.Fatalf("end=%s, want %s", got, want)
	}
}
