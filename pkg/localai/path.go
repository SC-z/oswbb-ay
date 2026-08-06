package localai

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	runtimeDownloadURL = "https://github.com/ggml-org/llama.cpp/releases"
	modelDownloadURL   = "https://huggingface.co/Qwen/Qwen3-0.6B-GGUF"
)

func resolveRuntimePath(explicit string) (string, error) {
	candidates := buildRuntimeCandidates(explicit)
	return firstExistingFile(candidates, "未找到 llama.cpp runtime，请使用 --ai-runtime-path 指定 llama-cli")
}

func resolveModelPath(explicit string) (string, error) {
	candidates := buildModelCandidates(explicit)
	return firstExistingFile(candidates, fmt.Sprintf("未找到默认模型 %s，请使用 --ai-model-path 指定 GGUF 文件", defaultModelFile))
}

func buildRuntimeCandidates(explicit string) []string {
	name := "llama-cli"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}

	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	}

	if exeDir := executableDir(); exeDir != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, "runtime", runtime.GOOS+"-"+runtime.GOARCH, name),
			filepath.Join(exeDir, "runtime", name),
			filepath.Join(exeDir, "bin", name),
			filepath.Join(exeDir, name),
		)
	}

	candidates = append(candidates,
		filepath.Join("runtime", runtime.GOOS+"-"+runtime.GOARCH, name),
		filepath.Join("runtime", name),
		filepath.Join("bin", name),
		name,
	)
	return candidates
}

func buildModelCandidates(explicit string) []string {
	var candidates []string
	if explicit != "" {
		candidates = append(candidates, explicit)
	}

	if exeDir := executableDir(); exeDir != "" {
		candidates = append(candidates,
			filepath.Join(exeDir, "models", defaultModelFile),
			filepath.Join(exeDir, "models", "Qwen3-0.6B-GGUF", defaultModelFile),
			filepath.Join(exeDir, defaultModelFile),
		)
	}

	candidates = append(candidates,
		filepath.Join("models", defaultModelFile),
		filepath.Join("models", "Qwen3-0.6B-GGUF", defaultModelFile),
		defaultModelFile,
	)
	return candidates
}

func firstExistingFile(candidates []string, notFoundMessage string) (string, error) {
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}

		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return candidate, nil
		}

		if isBareName(candidate) {
			if resolved, err := exec.LookPath(candidate); err == nil {
				return resolved, nil
			}
		}
	}
	return "", fmt.Errorf(notFoundMessage)
}

func isBareName(candidate string) bool {
	return candidate == filepath.Base(candidate) && !strings.ContainsRune(candidate, filepath.Separator)
}

func runtimeDownloadMessage() string {
	return fmt.Sprintf("下载地址: %s", runtimeDownloadURL)
}

func modelDownloadMessage() string {
	return fmt.Sprintf("下载地址: %s", modelDownloadURL)
}

func executableDir() string {
	path, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(path)
}
