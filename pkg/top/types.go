package top

import "time"

// TopSnapshot 对应 top 命令的一个快照点
type TopSnapshot struct {
	Timestamp time.Time `json:"timestamp"`

	// Load Average
	Load1  float64 `json:"load_1"`
	Load5  float64 `json:"load_5"`
	Load15 float64 `json:"load_15"`

	// Tasks
	TaskTotal    int `json:"task_total"`
	TaskRunning  int `json:"task_running"`
	TaskSleeping int `json:"task_sleeping"`
	TaskStopped  int `json:"task_stopped"`
	TaskZombie   int `json:"task_zombie"`

	// CPU Usage (%)
	CpuUser  float64 `json:"cpu_user"`
	CpuSys   float64 `json:"cpu_sys"`
	CpuNice  float64 `json:"cpu_nice"`
	CpuIdle  float64 `json:"cpu_idle"`
	CpuWait  float64 `json:"cpu_wait"`
	CpuHi    float64 `json:"cpu_hi"`
	CpuSi    float64 `json:"cpu_si"`
	CpuSteal float64 `json:"cpu_steal"`
}

// TopLog 包含所有解析后的快照
type TopLog struct {
	Snapshots []TopSnapshot `json:"snapshots"`
}

// GetTimeRange 获取数据的时间范围
func (l *TopLog) GetTimeRange() (time.Time, time.Time) {
	if len(l.Snapshots) == 0 {
		return time.Time{}, time.Time{}
	}
	return l.Snapshots[0].Timestamp, l.Snapshots[len(l.Snapshots)-1].Timestamp
}
