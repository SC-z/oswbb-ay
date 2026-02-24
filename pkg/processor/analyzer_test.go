package processor

import (
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"testing"
	"time"
)

type timeRangeStub struct {
	start time.Time
	end   time.Time
}

func (s timeRangeStub) GetTimeRange() (time.Time, time.Time) {
	return s.start, s.end
}

func TestResolveTimeRangeDefault(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := timeRangeStub{start: start, end: end}

	gotStart, gotEnd, usedDefault, err := resolveTimeRange(log, "", "", loc)
	if err != nil {
		t.Fatalf("resolveTimeRange 返回错误: %v", err)
	}
	if !usedDefault {
		t.Fatalf("期望使用默认时间范围")
	}
	if !gotStart.Equal(start) || !gotEnd.Equal(end) {
		t.Fatalf("返回的时间范围不正确: got (%s, %s)", gotStart, gotEnd)
	}
}

func TestResolveTimeRangeCustom(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := timeRangeStub{start: start, end: end}

	startStr := "2024-09-10 09:00:00"
	endStr := "2024-09-10 11:00:00"

	gotStart, gotEnd, usedDefault, err := resolveTimeRange(log, startStr, endStr, loc)
	if err != nil {
		t.Fatalf("resolveTimeRange 返回错误: %v", err)
	}
	if usedDefault {
		t.Fatalf("期望使用自定义时间范围")
	}

	wantStart, _ := time.ParseInLocation(TimeLayout, startStr, loc)
	wantEnd, _ := time.ParseInLocation(TimeLayout, endStr, loc)

	if !gotStart.Equal(wantStart) || !gotEnd.Equal(wantEnd) {
		t.Fatalf("返回的时间范围不正确: got (%s, %s)", gotStart, gotEnd)
	}
}

func TestResolveTimeRangeInvalid(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	start := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	end := start.Add(2 * time.Hour)
	log := timeRangeStub{start: start, end: end}

	if _, _, _, err := resolveTimeRange(log, "invalid", "2024-09-10 11:00:00", loc); err == nil {
		t.Fatalf("时间格式错误时应返回错误")
	}
}

func TestOutputFileExt(t *testing.T) {
	tests := []struct {
		name   string
		format string
		want   string
	}{
		{name: "html", format: "html", want: "html"},
		{name: "json", format: "json", want: "json"},
		{name: "csv", format: "csv", want: "csv"},
		{name: "ml maps to csv", format: "ml", want: "csv"},
		{name: "unknown maps to csv", format: "unknown", want: "csv"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := outputFileExt(tc.format); got != tc.want {
				t.Fatalf("outputFileExt(%q) = %q, want %q", tc.format, got, tc.want)
			}
		})
	}
}

func TestSortIOStatDataByTimestamp(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	t1 := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	t2 := t1.Add(10 * time.Minute)
	t3 := t1.Add(20 * time.Minute)

	data := []iostat.IOStatData{
		{Timestamp: t3},
		{Timestamp: t1},
		{Timestamp: t2},
	}

	sortIOStatDataByTimestamp(data)

	if !data[0].Timestamp.Equal(t1) || !data[1].Timestamp.Equal(t2) || !data[2].Timestamp.Equal(t3) {
		t.Fatalf("iostat 合并数据未按时间升序排序: got %v, %v, %v", data[0].Timestamp, data[1].Timestamp, data[2].Timestamp)
	}
}

func TestSortMemInfoDataByTimestamp(t *testing.T) {
	loc := time.FixedZone("CST", 8*3600)
	t1 := time.Date(2024, time.September, 10, 8, 0, 0, 0, loc)
	t2 := t1.Add(10 * time.Minute)
	t3 := t1.Add(20 * time.Minute)

	data := []meminfo.MemStatData{
		{Timestamp: t2},
		{Timestamp: t3},
		{Timestamp: t1},
	}

	sortMemInfoDataByTimestamp(data)

	if !data[0].Timestamp.Equal(t1) || !data[1].Timestamp.Equal(t2) || !data[2].Timestamp.Equal(t3) {
		t.Fatalf("meminfo 合并数据未按时间升序排序: got %v, %v, %v", data[0].Timestamp, data[1].Timestamp, data[2].Timestamp)
	}
}
