package output

import (
	"context"
	"fmt"
	"os"
)

type OutputRequest struct {
	Format   Format
	Data     []byte
	Path     string
	ToStdout bool
}

type OutputSink interface {
	Write(ctx context.Context, req OutputRequest) error
}

type FileSink struct{}

func (FileSink) Write(ctx context.Context, req OutputRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if req.ToStdout {
		_, err := os.Stdout.Write(req.Data)
		return err
	}
	if req.Path == "" {
		return fmt.Errorf("output path 不能为空")
	}
	return os.WriteFile(req.Path, req.Data, 0o644)
}
