package output

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
)

// CSVFormatter CSV格式输出器
type CSVFormatter struct{}

// NewCSVFormatter 创建CSV输出器
func NewCSVFormatter() *CSVFormatter {
	return &CSVFormatter{}
}

// OutputIOStatData 输出iostat数据为CSV格式
func (f *CSVFormatter) OutputIOStatData(data []IOStatRawMetrics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	headers := []string{
		"timestamp",
		"device",
		// "cpu_user",
		// "cpu_nice",
		// "cpu_system",
		// "cpu_iowait",
		// "cpu_steal",
		// "cpu_idle",
		"read_req_per_sec",
		"write_req_per_sec",
		"read_kb_per_sec",
		"write_kb_per_sec",
		"read_merge_per_sec",
		"write_merge_per_sec",
		"read_await",
		"write_await",
		"avg_queue_size",
		"avg_req_size",
		// "utilization",
	}

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入CSV头部失败: %v", err)
	}

	// 按设备分组数据
	deviceMap := make(map[string][]IOStatRawMetrics)
	var devices []string

	for _, metrics := range data {
		if _, exists := deviceMap[metrics.Device]; !exists {
			deviceMap[metrics.Device] = []IOStatRawMetrics{}
			devices = append(devices, metrics.Device)
		}
		deviceMap[metrics.Device] = append(deviceMap[metrics.Device], metrics)
	}

	// 简单的设备排序
	// sort.Strings(devices) // 既然要保持原有的发现顺序或者想要确定性顺序，可以排序。为了编译通过，需要import sort。
	// 这里为了避免引入额外import导致的不一致（如果没有import sort），我手动检查一下是否已有sort import。
	// 原文件没有sort import。为了安全起见，我这里不排序了，或者我添加import。
	// 鉴于用户要求“分Sheet”，按设备聚类是核心。顺序倒不是最关键，只要同一设备的在一起即可。
	// 直接遍历 devices 列表即可。

	for _, device := range devices {
		metricsList := deviceMap[device]
		for _, metrics := range metricsList {
			avgReqSizeStr := "NA"
			if metrics.AvgReqSize != nil {
				avgReqSizeStr = strconv.FormatFloat(*metrics.AvgReqSize, 'f', 2, 64)
			}
			record := []string{
				metrics.Timestamp,
				metrics.Device,
				// strconv.FormatFloat(metrics.CPUUser, 'f', 2, 64),
				// strconv.FormatFloat(metrics.CPUNice, 'f', 2, 64),
				// strconv.FormatFloat(metrics.CPUSystem, 'f', 2, 64),
				// strconv.FormatFloat(metrics.CPUIOWait, 'f', 2, 64),
				// strconv.FormatFloat(metrics.CPUSteal, 'f', 2, 64),
				// strconv.FormatFloat(metrics.CPUIdle, 'f', 2, 64),
				strconv.FormatFloat(metrics.ReadReqPerSec, 'f', 2, 64),
				strconv.FormatFloat(metrics.WriteReqPerSec, 'f', 2, 64),
				strconv.FormatFloat(metrics.ReadKBPerSec, 'f', 2, 64),
				strconv.FormatFloat(metrics.WriteKBPerSec, 'f', 2, 64),
				strconv.FormatFloat(metrics.ReadMergePerSec, 'f', 2, 64),
				strconv.FormatFloat(metrics.WriteMergePerSec, 'f', 2, 64),
				strconv.FormatFloat(metrics.ReadAwait, 'f', 2, 64),
				strconv.FormatFloat(metrics.WriteAwait, 'f', 2, 64),
				strconv.FormatFloat(metrics.AvgQueueSize, 'f', 2, 64),
				avgReqSizeStr,
				// strconv.FormatFloat(metrics.Utilization, 'f', 2, 64),
			}

			if err := writer.Write(record); err != nil {
				return fmt.Errorf("写入CSV数据行失败: %v", err)
			}
		}
	}

	fmt.Printf("已将iostat数据写入文件: %s\n", filename)
	return nil
}

// OutputMemInfoData 输出meminfo数据为CSV格式
func (f *CSVFormatter) OutputMemInfoData(data []MemInfoRawMetrics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	headers := []string{
		"timestamp",
		"mem_total",
		"mem_free",
		"mem_available",
		"buffers",
		"cached",
		"s_reclaimable",
		"s_unreclaim",
		"anon_pages",
		"swap_total",
		"swap_free",
	}

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入CSV头部失败: %v", err)
	}

	// 写入数据行
	for _, metrics := range data {
		record := []string{
			metrics.Timestamp,
			strconv.FormatInt(metrics.MemTotal, 10),
			strconv.FormatInt(metrics.MemFree, 10),
			strconv.FormatInt(metrics.MemAvailable, 10),
			strconv.FormatInt(metrics.Buffers, 10),
			strconv.FormatInt(metrics.Cached, 10),
			strconv.FormatInt(metrics.SReclaimable, 10),
			strconv.FormatInt(metrics.SUnreclaim, 10),
			strconv.FormatInt(metrics.AnonPages, 10),
			strconv.FormatInt(metrics.SwapTotal, 10),
			strconv.FormatInt(metrics.SwapFree, 10),
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV数据行失败: %v", err)
		}
	}

	fmt.Printf("已将meminfo数据写入文件: %s\n", filename)
	return nil
}

// OutputTopData 输出top数据为CSV格式
func (f *CSVFormatter) OutputTopData(data []TopRawMetrics, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建文件失败: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 写入CSV头部
	headers := []string{
		"timestamp",
		"load_1",
		"load_5",
		"load_15",
		"task_total",
		"task_running",
		"task_sleeping",
		"task_stopped",
		"task_zombie",
		"cpu_user",
		"cpu_sys",
		"cpu_idle",
		"cpu_wait",
		"cpu_steal",
	}

	if err := writer.Write(headers); err != nil {
		return fmt.Errorf("写入CSV头部失败: %v", err)
	}

	// 写入数据行
	for _, metrics := range data {
		record := []string{
			metrics.Timestamp,
			strconv.FormatFloat(metrics.Load1, 'f', 2, 64),
			strconv.FormatFloat(metrics.Load5, 'f', 2, 64),
			strconv.FormatFloat(metrics.Load15, 'f', 2, 64),
			strconv.Itoa(metrics.TaskTotal),
			strconv.Itoa(metrics.TaskRunning),
			strconv.Itoa(metrics.TaskSleeping),
			strconv.Itoa(metrics.TaskStopped),
			strconv.Itoa(metrics.TaskZombie),
			strconv.FormatFloat(metrics.CpuUser, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuSys, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuIdle, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuWait, 'f', 1, 64),
			strconv.FormatFloat(metrics.CpuSteal, 'f', 1, 64),
		}

		if err := writer.Write(record); err != nil {
			return fmt.Errorf("写入CSV数据行失败: %v", err)
		}
	}

	fmt.Printf("已将top数据写入文件: %s\n", filename)
	return nil
}
