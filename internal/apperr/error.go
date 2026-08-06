package apperr

import (
	"errors"
	"fmt"
)

type Kind string

const (
	KindAnalysis Kind = "analysis"
	KindConfig   Kind = "config"
	KindAI       Kind = "ai"
	KindIO       Kind = "io"
	KindInternal Kind = "internal"
)

type Error struct {
	Kind    Kind
	Module  string
	Message string
	Err     error
}

func New(kind Kind, module, message string) error {
	return &Error{Kind: kind, Module: module, Message: message}
}

func Wrap(kind Kind, module, message string, err error) error {
	return &Error{Kind: kind, Module: module, Message: message, Err: err}
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	prefix := string(e.Kind)
	if e.Module != "" {
		prefix += "/" + e.Module
	}
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", prefix, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", prefix, e.Message)
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *Error) Is(target error) bool {
	if e == nil {
		return false
	}
	targetErr, ok := target.(*Error)
	if !ok || targetErr.Kind == "" {
		return false
	}
	if e.Kind != targetErr.Kind {
		return false
	}
	return targetErr.Module == "" || e.Module == targetErr.Module
}

func KindOf(err error) Kind {
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr.Kind
	}
	return ""
}

func ModuleOf(err error) string {
	var appErr *Error
	if errors.As(err, &appErr) {
		return appErr.Module
	}
	return ""
}
