package meminfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"oswbb-analyse/pkg/common"
)

// MemStatData 内存状态数据快照
type MemStatData struct {
	Timestamp time.Time `json:"timestamp"`
	MemStats  MemStats  `json:"memstats"`
}

// MemStats 内存统计信息
type MemStats struct {
	// 基础内存信息
	MemTotal     int64 `json:"mem_total"`      // 总内存
	MemFree      int64 `json:"mem_free"`       // 空闲内存
	MemAvailable int64 `json:"mem_available"`  // 可用内存
	Buffers      int64 `json:"buffers"`        // 缓冲区
	Cached       int64 `json:"cached"`         // 缓存

	// 活跃/非活跃内存
	Active   int64 `json:"active"`   // 活跃内存
	Inactive int64 `json:"inactive"` // 非活跃内存

	// 匿名页和文件页
	ActiveAnon   int64 `json:"active_anon"`   // 活跃匿名页
	InactiveAnon int64 `json:"inactive_anon"` // 非活跃匿名页
	ActiveFile   int64 `json:"active_file"`   // 活跃文件页
	InactiveFile int64 `json:"inactive_file"` // 非活跃文件页

	// 交换区信息
	SwapTotal  int64 `json:"swap_total"`  // 交换区总量
	SwapFree   int64 `json:"swap_free"`   // 交换区空闲
	SwapCached int64 `json:"swap_cached"` // 交换缓存

	// 其他重要指标
	AnonPages    int64 `json:"anon_pages"`    // 匿名页总数
	Dirty        int64 `json:"dirty"`         // 脏页
	Writeback    int64 `json:"writeback"`     // 回写页
	Slab         int64 `json:"slab"`          // Slab缓存
	SReclaimable int64 `json:"s_reclaimable"` // 可回收Slab
	SUnreclaim   int64 `json:"s_unreclaim"`   // 不可回收Slab
	Dentry       int64 `json:"dentry"`        // dentry缓存
	KernelStack  int64 `json:"kernel_stack"`  // 内核栈
	PageTables   int64 `json:"page_tables"`   // 页表
	Percpu       int64 `json:"percpu"`        // Percpu
	KReclaimable int64 `json:"k_reclaimable"` // 可回收内核内存
	Committed    int64 `json:"committed"`     // 已提交内存
	VmallocUsed  int64 `json:"vmalloc_used"`  // Vmalloc使用

	// 大页信息
	HugePagesTotal int64 `json:"hugepages_total"` // 大页总数
	HugePagesFree  int64 `json:"hugepages_free"`  // 大页空闲数
	Hugepagesize   int64 `json:"hugepagesize"`    // 大页大小
}

// MemInfoLog 完整内存日志结构
type MemInfoLog struct {
	Data []MemStatData `json:"data"`
}

// MemInfoParser 解析器
type MemInfoParser struct{}

// ParseFile 解析meminfo文件
func (p *MemInfoParser) ParseFile(filename string) (*MemInfoLog, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	log := &MemInfoLog{
		Data: make([]MemStatData, 0),
	}

	scanner := bufio.NewScanner(file)
	var currentSnapshot *MemStatData

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.HasPrefix(line, "zzz ***"):
			// 保存前一个快照
			if currentSnapshot != nil {
				log.Data = append(log.Data, *currentSnapshot)
			}
			// 解析时间戳
			timestamp, err := p.parseTimestamp(line)
			if err != nil {
				continue
			}
			// 创建新的快照
			currentSnapshot = &MemStatData{
				Timestamp: timestamp,
			}

		case line != "" && currentSnapshot != nil:
			// 解析内存数据行
			p.parseMemoryLine(line, &currentSnapshot.MemStats)
		}
	}

	// 添加最后一个快照
	if currentSnapshot != nil {
		log.Data = append(log.Data, *currentSnapshot)
	}

	return log, scanner.Err()
}

// parseTimestamp 解析时间戳
func (p *MemInfoParser) parseTimestamp(line string) (time.Time, error) {
	// zzz ***Thu Sep 4 14:00:00 CST 2025
	parts := strings.Fields(line)
	if len(parts) < 7 {
		return time.Time{}, fmt.Errorf("invalid timestamp line")
	}

	timeStr := strings.Join(parts[2:], " ")
	layout := "Jan 2 15:04:05 MST 2006"
	parsedTime, err := time.Parse(layout, timeStr)
	if err != nil {
		return time.Time{}, err
	}

	// 转换为CST时区
	cst := time.FixedZone("CST", 8*3600)
	return parsedTime.In(cst), nil
}

// parseMemoryLine 解析内存信息行
func (p *MemInfoParser) parseMemoryLine(line string, memStats *MemStats) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	key := strings.TrimSuffix(parts[0], ":")
	valueStr := parts[1]
	value, err := strconv.ParseInt(valueStr, 10, 64)
	if err != nil {
		return
	}

	// 根据key设置对应的字段
	switch key {
	case "MemTotal":
		memStats.MemTotal = value
	case "MemFree":
		memStats.MemFree = value
	case "MemAvailable":
		memStats.MemAvailable = value
	case "Buffers":
		memStats.Buffers = value
	case "Cached":
		memStats.Cached = value
	case "Active":
		memStats.Active = value
	case "Inactive":
		memStats.Inactive = value
	case "Active(anon)":
		memStats.ActiveAnon = value
	case "Inactive(anon)":
		memStats.InactiveAnon = value
	case "Active(file)":
		memStats.ActiveFile = value
	case "Inactive(file)":
		memStats.InactiveFile = value
	case "SwapTotal":
		memStats.SwapTotal = value
	case "SwapFree":
		memStats.SwapFree = value
	case "SwapCached":
		memStats.SwapCached = value
	case "AnonPages":
		memStats.AnonPages = value
	case "Dirty":
		memStats.Dirty = value
	case "Writeback":
		memStats.Writeback = value
	case "Slab":
		memStats.Slab = value
	case "SReclaimable":
		memStats.SReclaimable = value
	case "SUnreclaim":
		memStats.SUnreclaim = value
	case "Dentry":
		memStats.Dentry = value
	case "KernelStack":
		memStats.KernelStack = value
	case "PageTables":
		memStats.PageTables = value
	case "Percpu":
		memStats.Percpu = value
	case "KReclaimable":
		memStats.KReclaimable = value
	case "Committed_AS":
		memStats.Committed = value
	case "VmallocUsed":
		memStats.VmallocUsed = value
	case "HugePages_Total":
		memStats.HugePagesTotal = value
	case "HugePages_Free":
		memStats.HugePagesFree = value
	case "Hugepagesize":
		memStats.Hugepagesize = value
	}
}

// GetTimeRange 获取数据的时间范围
func (log *MemInfoLog) GetTimeRange() (time.Time, time.Time) {
	if len(log.Data) == 0 {
		return time.Time{}, time.Time{}
	}
	return log.Data[0].Timestamp, log.Data[len(log.Data)-1].Timestamp
}

// GetMemoryUsageTrend 获取内存使用率趋势
func (log *MemInfoLog) GetMemoryUsageTrend(startTime, endTime time.Time) common.TimeValueList {
	var result []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		// 计算内存使用率：(Total - Available) / Total * 100
		if data.MemStats.MemTotal > 0 {
			usagePercent := float64(data.MemStats.MemTotal-data.MemStats.MemAvailable) / float64(data.MemStats.MemTotal) * 100
			result = append(result, common.TimeValue{
				Time:  data.Timestamp,
				Value: usagePercent,
			})
		}
	}

	return common.TimeValueList(result)
}

// GetSwapUsageTrend 获取交换区使用率趋势
func (log *MemInfoLog) GetSwapUsageTrend(startTime, endTime time.Time) common.TimeValueList {
	var result []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		// 计算交换区使用率：(SwapTotal - SwapFree) / SwapTotal * 100
		if data.MemStats.SwapTotal > 0 {
			swapUsed := data.MemStats.SwapTotal - data.MemStats.SwapFree
			usagePercent := float64(swapUsed) / float64(data.MemStats.SwapTotal) * 100
			result = append(result, common.TimeValue{
				Time:  data.Timestamp,
				Value: usagePercent,
			})
		}
	}

	return common.TimeValueList(result)
}

// GetCacheUsageTrend 获取缓存使用趋势（Buffer + Cache）
func (log *MemInfoLog) GetCacheUsageTrend(startTime, endTime time.Time) common.TimeValueList {
	var result []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		// Buffer + Cache 占总内存的比例
		if data.MemStats.MemTotal > 0 {
			cacheTotal := data.MemStats.Buffers + data.MemStats.Cached
			cachePercent := float64(cacheTotal) / float64(data.MemStats.MemTotal) * 100
			result = append(result, common.TimeValue{
				Time:  data.Timestamp,
				Value: cachePercent,
			})
		}
	}

	return common.TimeValueList(result)
}
