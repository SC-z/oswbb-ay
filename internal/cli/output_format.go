package cli

import (
	"fmt"
	"path/filepath"
	"strings"
)

// TrailingOutputFormat recovers -o/--o from args left unparsed by Go's flag
// package. This matters when a shell-expanded glob follows -f:
//
//	oswbb-analyse -f ./* -o html
//
// The standard flag parser stops at the first expanded filename, so -o would
// otherwise be treated as a positional argument and the CLI would silently keep
// its default output format.
func TrailingOutputFormat(args []string) (string, bool, error) {
	var outputFormat string
	found := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "-o" || arg == "--o" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return "", false, fmt.Errorf("%s requires an output format value", arg)
			}
			outputFormat = args[i+1]
			found = true
			i++
			continue
		}

		for _, prefix := range []string{"-o=", "--o="} {
			if strings.HasPrefix(arg, prefix) {
				value := strings.TrimPrefix(arg, prefix)
				if value == "" {
					return "", false, fmt.Errorf("%s requires an output format value", strings.TrimSuffix(prefix, "="))
				}
				outputFormat = value
				found = true
				break
			}
		}
	}

	return outputFormat, found, nil
}

// ExpandedInputDirectory turns shell-expanded input files back into the
// directory the user meant to analyze. For example:
//
//	oswbb-analyse -f ./* -o html
//
// arrives as -f <first-file> plus many positional args. The application only
// accepts one input path, so treating the common parent as the input preserves
// the intended "analyze this directory" behavior.
func ExpandedInputDirectory(inputPath string, args []string) (string, bool) {
	if inputPath == "" {
		return "", false
	}

	paths := append([]string{inputPath}, trailingPositionalPaths(args)...)
	if len(paths) < 2 {
		return "", false
	}

	dir := filepath.Clean(filepath.Dir(paths[0]))
	for _, path := range paths[1:] {
		if filepath.Clean(filepath.Dir(path)) != dir {
			return "", false
		}
	}
	return dir, true
}

func trailingPositionalPaths(args []string) []string {
	paths := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-o" || arg == "--o":
			i++
		case strings.HasPrefix(arg, "-o=") || strings.HasPrefix(arg, "--o="):
			continue
		case strings.HasPrefix(arg, "-"):
			continue
		default:
			paths = append(paths, arg)
		}
	}
	return paths
}
