package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
)

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Logger struct {
	out io.Writer
	min Level
}

func New(out io.Writer, min Level) *Logger {
	if out == nil {
		out = os.Stderr
	}
	return &Logger{out: out, min: min}
}

func Default() *Logger {
	return New(os.Stderr, LevelInfo)
}

func (l *Logger) Writer() io.Writer {
	if l == nil || l.out == nil {
		return os.Stderr
	}
	return l.out
}

func (l *Logger) Debugf(format string, args ...interface{}) {
	l.logf(LevelDebug, "DEBUG", format, args...)
}
func (l *Logger) Infof(format string, args ...interface{}) {
	l.logf(LevelInfo, "INFO", format, args...)
}
func (l *Logger) Warnf(format string, args ...interface{}) {
	l.logf(LevelWarn, "WARN", format, args...)
}
func (l *Logger) Errorf(format string, args ...interface{}) {
	l.logf(LevelError, "ERROR", format, args...)
}

func (l *Logger) logf(level Level, label, format string, args ...interface{}) {
	if l == nil {
		l = Default()
	}
	if level < l.min {
		return
	}
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.Writer(), "%s %s\n", label, strings.TrimRight(msg, "\n"))
}
