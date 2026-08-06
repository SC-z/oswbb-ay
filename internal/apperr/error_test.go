package apperr

import (
	"errors"
	"strings"
	"testing"
)

func TestWrapKeepsKindModuleAndCause(t *testing.T) {
	cause := errors.New("open input")
	err := Wrap(KindIO, "iostat", "load sample", cause)

	if !errors.Is(err, &Error{Kind: KindIO}) {
		t.Fatalf("wrapped error should match kind sentinel")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("wrapped error should match cause")
	}
	if KindOf(err) != KindIO {
		t.Fatalf("kind = %q, want %q", KindOf(err), KindIO)
	}
	if ModuleOf(err) != "iostat" {
		t.Fatalf("module = %q, want iostat", ModuleOf(err))
	}
	if !strings.Contains(err.Error(), "iostat") || !strings.Contains(err.Error(), "load sample") {
		t.Fatalf("error string lost context: %v", err)
	}
}

func TestNewClassifiesWithoutCause(t *testing.T) {
	err := New(KindConfig, "", "bad threshold")

	if !errors.Is(err, &Error{Kind: KindConfig}) {
		t.Fatalf("new error should match kind sentinel")
	}
	if KindOf(err) != KindConfig {
		t.Fatalf("kind = %q, want %q", KindOf(err), KindConfig)
	}
	if ModuleOf(err) != "" {
		t.Fatalf("module = %q, want empty", ModuleOf(err))
	}
}
