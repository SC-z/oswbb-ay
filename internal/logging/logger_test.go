package logging

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestLoggerWritesToConfiguredWriter(t *testing.T) {
	var buf bytes.Buffer
	logger := New(&buf, LevelInfo)

	logger.Infof("scan %s", "input")
	logger.Debugf("hidden")

	got := buf.String()
	if !strings.Contains(got, "INFO scan input") {
		t.Fatalf("info log missing: %q", got)
	}
	if strings.Contains(got, "hidden") {
		t.Fatalf("debug should be filtered at info level: %q", got)
	}
}

func TestDefaultLoggerUsesStderr(t *testing.T) {
	if Default().Writer() != os.Stderr {
		t.Fatalf("default logger should write to stderr")
	}
}
