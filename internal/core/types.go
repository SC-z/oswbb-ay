package core

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	legacyiostat "oswbb-analyse/pkg/iostat"
	legacymeminfo "oswbb-analyse/pkg/meminfo"
	legacytop "oswbb-analyse/pkg/top"
)

type FileType string

const (
	FileTypeIOStat  FileType = "iostat"
	FileTypeMeminfo FileType = "meminfo"
	FileTypeTop     FileType = "top"
)

type TimeRange struct {
	Start time.Time
	End   time.Time
}

func (r TimeRange) IsZero() bool {
	return r.Start.IsZero() && r.End.IsZero()
}

// AnalysisBundle is the small shared carrier for parsed module logs while
// pkg/processor remains the compatibility backend.
type AnalysisBundle struct {
	Hostname string
	IOStat   *legacyiostat.IOStatLog
	Meminfo  *legacymeminfo.MemInfoLog
	Top      *legacytop.TopLog
}

func DetectFileType(path string) (FileType, bool) {
	name := strings.ToLower(filepath.Base(path))
	if strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".dat") {
		return "", false
	}
	switch {
	case strings.Contains(name, "iostat"):
		return FileTypeIOStat, true
	case strings.Contains(name, "meminfo"):
		return FileTypeMeminfo, true
	case strings.Contains(name, "top"):
		return FileTypeTop, true
	default:
		return "", false
	}
}

func FileTypesForPath(path string) ([]FileType, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	seen := map[FileType]bool{}
	if !info.IsDir() {
		if fileType, ok := DetectFileType(path); ok {
			seen[fileType] = true
		}
		return sortedFileTypes(seen), nil
	}
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || strings.HasPrefix(d.Name(), ".") {
			return nil
		}
		if fileType, ok := DetectFileType(p); ok {
			seen[fileType] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sortedFileTypes(seen), nil
}

func sortedFileTypes(seen map[FileType]bool) []FileType {
	order := []FileType{FileTypeIOStat, FileTypeMeminfo, FileTypeTop}
	result := make([]FileType, 0, len(seen))
	for _, fileType := range order {
		if seen[fileType] {
			result = append(result, fileType)
		}
	}
	if len(result) == len(seen) {
		return result
	}
	for fileType := range seen {
		if fileType != FileTypeIOStat && fileType != FileTypeMeminfo && fileType != FileTypeTop {
			result = append(result, fileType)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}
