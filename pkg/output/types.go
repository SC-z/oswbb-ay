package output

import (
	"oswbb-analyse/pkg/iostat"
	"oswbb-analyse/pkg/meminfo"
	"oswbb-analyse/pkg/top"
	"time"
)

const (
	// TimestampFormat 时间戳格式常量 (与analyzer包保持一致)
	TimestampFormat = "2006-01-02 15:04:05"
)

// IOStatRawMetrics iostat原始指标（每个设备单独一行）
type IOStatRawMetrics struct {
	// 基础信息
	Timestamp string `json:"timestamp" csv:"timestamp"`
	Device    string `json:"device" csv:"device"`

	// CPU 指标
	CPUUser   float64 `json:"cpu_user" csv:"cpu_user"`
	CPUNice   float64 `json:"cpu_nice" csv:"cpu_nice"`
	CPUSystem float64 `json:"cpu_system" csv:"cpu_system"`
	CPUIOWait float64 `json:"cpu_iowait" csv:"cpu_iowait"`
	CPUSteal  float64 `json:"cpu_steal" csv:"cpu_steal"`
	CPUIdle   float64 `json:"cpu_idle" csv:"cpu_idle"`

	// I/O 吞吐量指标
	ReadReqPerSec    float64 `json:"read_req_per_sec" csv:"read_req_per_sec"`
	WriteReqPerSec   float64 `json:"write_req_per_sec" csv:"write_req_per_sec"`
	ReadKBPerSec     float64 `json:"read_kb_per_sec" csv:"read_kb_per_sec"`
	WriteKBPerSec    float64 `json:"write_kb_per_sec" csv:"write_kb_per_sec"`
	ReadMergePerSec  float64 `json:"read_merge_per_sec" csv:"read_merge_per_sec"`
	WriteMergePerSec float64 `json:"write_merge_per_sec" csv:"write_merge_per_sec"`

	// I/O 延迟和队列指标
	ReadAwait    float64  `json:"read_await" csv:"read_await"`
	WriteAwait   float64  `json:"write_await" csv:"write_await"`
	AvgQueueSize float64  `json:"avg_queue_size" csv:"avg_queue_size"`
	AvgReqSize   *float64 `json:"avg_req_size" csv:"avg_req_size"`
	// Utilization      float64 `json:"utilization" csv:"utilization"`
}

// MemInfoRawMetrics meminfo原始指标
type MemInfoRawMetrics struct {
	// 基础信息
	Timestamp string `json:"timestamp" csv:"timestamp"`

	// 内存指标 (单位:KB)
	MemTotal     int64 `json:"mem_total" csv:"mem_total"`
	MemFree      int64 `json:"mem_free" csv:"mem_free"`
	MemAvailable int64 `json:"mem_available" csv:"mem_available"`
	Buffers      int64 `json:"buffers" csv:"buffers"`
	Cached       int64 `json:"cached" csv:"cached"`
	SReclaimable int64 `json:"s_reclaimable" csv:"s_reclaimable"`
	SUnreclaim   int64 `json:"s_unreclaim" csv:"s_unreclaim"`
	AnonPages    int64 `json:"anon_pages" csv:"anon_pages"`

	// 交换分区指标 (单位:KB)
	SwapTotal int64 `json:"swap_total" csv:"swap_total"`
	SwapFree  int64 `json:"swap_free" csv:"swap_free"`
}

// TopRawMetrics top原始指标
type TopRawMetrics struct {
	Timestamp string `json:"timestamp" csv:"timestamp"`

	// Load Average
	Load1  float64 `json:"load_1" csv:"load_1"`
	Load5  float64 `json:"load_5" csv:"load_5"`
	Load15 float64 `json:"load_15" csv:"load_15"`

	// Tasks
	TaskTotal    int `json:"task_total" csv:"task_total"`
	TaskRunning  int `json:"task_running" csv:"task_running"`
	TaskSleeping int `json:"task_sleeping" csv:"task_sleeping"`
	TaskStopped  int `json:"task_stopped" csv:"task_stopped"`
	TaskZombie   int `json:"task_zombie" csv:"task_zombie"`

	// CPU
	CpuUser  float64 `json:"cpu_user" csv:"cpu_user"`
	CpuSys   float64 `json:"cpu_sys" csv:"cpu_sys"`
	CpuIdle  float64 `json:"cpu_idle" csv:"cpu_idle"`
	CpuWait  float64 `json:"cpu_wait" csv:"cpu_wait"`
	CpuSteal float64 `json:"cpu_steal" csv:"cpu_steal"`
}

// OutputFormatter 输出格式接口
type OutputFormatter interface {
	OutputIOStatData(data []IOStatRawMetrics, filename string) error
	OutputMemInfoData(data []MemInfoRawMetrics, filename string) error
	OutputTopData(data []TopRawMetrics, filename string) error
}

// isInTimeRange 检查时间是否在指定范围内
func isInTimeRange(timestamp, startTime, endTime time.Time) bool {
	return !timestamp.Before(startTime) && !timestamp.After(endTime)
}

// ConvertIOStatData 将iostat数据转换为原始指标格式（每个设备单独一行）
func ConvertIOStatData(iostatLog *iostat.IOStatLog, startTime, endTime time.Time) []IOStatRawMetrics {
	var result []IOStatRawMetrics

	for _, data := range iostatLog.Data {
		if !isInTimeRange(data.Timestamp, startTime, endTime) {
			continue
		}

		timestampStr := data.Timestamp.Format(TimestampFormat)

		// 为每个设备创建一行数据
		for _, device := range data.Devices {
			metrics := createIOStatMetrics(timestampStr, &data, &device)
			result = append(result, metrics)
		}
	}

	return result
}

// createIOStatMetrics 创建IOStat指标结构体
func createIOStatMetrics(timestamp string, data *iostat.IOStatData, device *iostat.DeviceStats) IOStatRawMetrics {
	return IOStatRawMetrics{
		Timestamp: timestamp,
		Device:    device.Device,

		// CPU 指标
		CPUUser:   data.CPU.User,
		CPUNice:   data.CPU.Nice,
		CPUSystem: data.CPU.System,
		CPUIOWait: data.CPU.IOWait,
		CPUSteal:  data.CPU.Steal,
		CPUIdle:   data.CPU.Idle,

		// I/O 指标
		ReadReqPerSec:    device.ReadReqPerSec,
		WriteReqPerSec:   device.WriteReqPerSec,
		ReadKBPerSec:     device.ReadKBPerSec,
		WriteKBPerSec:    device.WriteKBPerSec,
		ReadMergePerSec:  device.ReadMergePerSec,
		WriteMergePerSec: device.WriteMergePerSec,
		ReadAwait:        device.ReadAwait,
		WriteAwait:       device.WriteAwait,
		AvgQueueSize:     device.AvgQueueSize,
		AvgReqSize:       device.AvgReqSize,
		// Utilization:      device.Utilization,
	}
}

// ConvertMemInfoData 将meminfo数据转换为原始指标格式
func ConvertMemInfoData(memLog *meminfo.MemInfoLog, startTime, endTime time.Time) []MemInfoRawMetrics {
	var result []MemInfoRawMetrics

	for _, data := range memLog.Data {
		if !isInTimeRange(data.Timestamp, startTime, endTime) {
			continue
		}

		metrics := createMemInfoMetrics(data.Timestamp.Format(TimestampFormat), &data.MemStats)
		result = append(result, metrics)
	}

	return result
}

// createMemInfoMetrics 创建MemInfo指标结构体
func createMemInfoMetrics(timestamp string, memStats *meminfo.MemStats) MemInfoRawMetrics {
	return MemInfoRawMetrics{
		Timestamp:    timestamp,
		MemTotal:     memStats.MemTotal,
		MemFree:      memStats.MemFree,
		MemAvailable: memStats.MemAvailable,
		Buffers:      memStats.Buffers,
		Cached:       memStats.Cached,
		SReclaimable: memStats.SReclaimable,
		SUnreclaim:   memStats.SUnreclaim,
		AnonPages:    memStats.AnonPages,
		SwapTotal:    memStats.SwapTotal,
		SwapFree:     memStats.SwapFree,
	}
}

// ConvertTopData 将top数据转换为原始指标格式
func ConvertTopData(topLog *top.TopLog, startTime, endTime time.Time) []TopRawMetrics {
	var result []TopRawMetrics

	for _, snap := range topLog.Snapshots {
		if !isInTimeRange(snap.Timestamp, startTime, endTime) {
			continue
		}

		metrics := TopRawMetrics{
			Timestamp:    snap.Timestamp.Format(TimestampFormat),
			Load1:        snap.Load1,
			Load5:        snap.Load5,
			Load15:       snap.Load15,
			TaskTotal:    snap.TaskTotal,
			TaskRunning:  snap.TaskRunning,
			TaskSleeping: snap.TaskSleeping,
			TaskStopped:  snap.TaskStopped,
			TaskZombie:   snap.TaskZombie,
			CpuUser:      snap.CpuUser,
			CpuSys:       snap.CpuSys,
			CpuIdle:      snap.CpuIdle,
			CpuWait:      snap.CpuWait,
			CpuSteal:     snap.CpuSteal,
		}
		result = append(result, metrics)
	}

	return result
}
