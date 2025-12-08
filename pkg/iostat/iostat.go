package iostat

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"oswbb-analyse/pkg/common"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IOStatData iostat数据快照
type IOStatData struct {
	Timestamp time.Time     `json:"timestamp"`
	CPU       CPUStats      `json:"cpu"`
	Devices   []DeviceStats `json:"devices"`
}

// CPUStats CPU统计
type CPUStats struct {
	User   float64 `json:"user"`
	Nice   float64 `json:"nice"`
	System float64 `json:"system"`
	IOWait float64 `json:"iowait"`
	Steal  float64 `json:"steal"`
	Idle   float64 `json:"idle"`
}

// DeviceStats 设备I/O统计
type DeviceStats struct {
	Device string `json:"device"`

	// 读操作指标
	ReadReqPerSec   float64 `json:"r_s"`
	ReadKBPerSec    float64 `json:"rkb_s"`
	ReadMergePerSec float64 `json:"rrqm_s"`
	ReadMergePct    float64 `json:"rrqm_pct"`
	ReadAwait       float64 `json:"r_await"`
	ReadReqSize     float64 `json:"rareq_sz"`

	// 写操作指标
	WriteReqPerSec   float64 `json:"w_s"`
	WriteKBPerSec    float64 `json:"wkb_s"`
	WriteMergePerSec float64 `json:"wrqm_s"`
	WriteMergePct    float64 `json:"wrqm_pct"`
	WriteAwait       float64 `json:"w_await"`
	WriteReqSize     float64 `json:"wareq_sz"`

	// 丢弃操作指标
	DiscardReqPerSec   float64 `json:"d_s"`
	DiscardKBPerSec    float64 `json:"dkb_s"`
	DiscardMergePerSec float64 `json:"drqm_s"`
	DiscardMergePct    float64 `json:"drqm_pct"`
	DiscardAwait       float64 `json:"d_await"`
	DiscardReqSize     float64 `json:"dareq_sz"`

	// 队列和利用率
	AvgQueueSize float64 `json:"aqu_sz"`
	// Utilization  float64 `json:"util"`
}

// IOStatLog 完整日志结构
type IOStatLog struct {
	Header string       `json:"header"`
	Data   []IOStatData `json:"data"`
}

// IOStatParser 解析器
type IOStatParser struct{}

// ParseFile 解析iostat文件
func (p *IOStatParser) ParseFile(filename string) (*IOStatLog, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	log := &IOStatLog{
		Data: make([]IOStatData, 0),
	}

	scanner := bufio.NewScanner(file)
	var currentSnapshot *IOStatData

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		switch {
		case strings.HasPrefix(line, "Linux OSWbb"):
			log.Header = line

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
			// 创建新的快照点
			currentSnapshot = &IOStatData{
				Timestamp: timestamp,
				Devices:   make([]DeviceStats, 0),
			}

		case strings.Contains(line, "%user") && currentSnapshot != nil:
			// 读取下一行的CPU数据
			if scanner.Scan() {
				cpuLine := strings.TrimSpace(scanner.Text())
				cpu, err := p.parseCPUStats(cpuLine)
				if err == nil {
					currentSnapshot.CPU = cpu
				}
			}

		case strings.HasPrefix(line, "Device"):
			// 跳过设备表头
			continue

		case line != "" && !strings.Contains(line, "avg-cpu") && currentSnapshot != nil:
			// 解析设备数据
			device, err := p.parseDeviceStats(line)
			if err == nil {
				currentSnapshot.Devices = append(currentSnapshot.Devices, device)
			}
		}
	}

	// 添加最后一个快照
	if currentSnapshot != nil {
		log.Data = append(log.Data, *currentSnapshot)
	}

	return log, scanner.Err()
}

// parseTimestamp 解析时间戳
func (p *IOStatParser) parseTimestamp(line string) (time.Time, error) {
	// zzz ***Fri Aug 29 16:00:04 CST 2025
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

// parseCPUStats 解析CPU统计
func (p *IOStatParser) parseCPUStats(line string) (CPUStats, error) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return CPUStats{}, fmt.Errorf("invalid CPU stats line")
	}

	var cpu CPUStats
	var err error

	cpu.User, err = strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return cpu, err
	}
	cpu.Nice, err = strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return cpu, err
	}
	cpu.System, err = strconv.ParseFloat(fields[2], 64)
	if err != nil {
		return cpu, err
	}
	cpu.IOWait, err = strconv.ParseFloat(fields[3], 64)
	if err != nil {
		return cpu, err
	}
	cpu.Steal, err = strconv.ParseFloat(fields[4], 64)
	if err != nil {
		return cpu, err
	}
	cpu.Idle, err = strconv.ParseFloat(fields[5], 64)
	if err != nil {
		return cpu, err
	}

	return cpu, nil
}

// parseDeviceStats 解析设备统计 - 兼容不同格式
func (p *IOStatParser) parseDeviceStats(line string) (DeviceStats, error) {
	fields := strings.Fields(line)
	if len(fields) < 15 {
		return DeviceStats{}, fmt.Errorf("Abnormal raw data: expected at least 15 fields, got %d", len(fields))
	}

	// 跳过RAID设备(md*)
	deviceName := fields[0]
	if strings.HasPrefix(deviceName, "md") {
		// 忽略RAID设备
		return DeviceStats{}, fmt.Errorf("skipping RAID device: %s", deviceName)
	}

	device := DeviceStats{
		Device: deviceName,
	}

	// 根据字段数量判断格式
	numFields := len(fields) - 1 // 减去设备名

	if numFields == 15 {
		// 新格式: r/s w/s rkB/s wkB/s rrqm/s wrqm/s %rrqm %wrqm r_await w_await aqu-sz rareq-sz wareq-sz svctm %util
		values := make([]float64, 15)
		for i := 0; i < 15; i++ {
			val, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil {
				return device, fmt.Errorf("failed to parse field %d: %v", i+1, err)
			}
			values[i] = val
		}

		// 新格式字段映射
		device.ReadReqPerSec = values[0]    // r/s
		device.WriteReqPerSec = values[1]   // w/s
		device.ReadKBPerSec = values[2]     // rkB/s
		device.WriteKBPerSec = values[3]    // wkB/s
		device.ReadMergePerSec = values[4]  // rrqm/s
		device.WriteMergePerSec = values[5] // wrqm/s
		device.ReadMergePct = values[6]     // %rrqm
		device.WriteMergePct = values[7]    // %wrqm
		device.ReadAwait = values[8]        // r_await
		device.WriteAwait = values[9]       // w_await
		device.AvgQueueSize = values[10]    // aqu-sz
		device.ReadReqSize = values[11]     // rareq-sz
		device.WriteReqSize = values[12]    // wareq-sz
		// values[13] = svctm (服务时间，暂不使用)ls

		// device.Utilization = values[14] // %util

		// 新格式没有discard相关字段，设为0
		device.DiscardReqPerSec = 0
		device.DiscardKBPerSec = 0
		device.DiscardMergePerSec = 0
		device.DiscardMergePct = 0
		device.DiscardAwait = 0
		device.DiscardReqSize = 0

	} else if numFields == 20 {
		// 旧格式: r/s rkB/s rrqm/s %rrqm r_await rareq-sz w/s wkB/s wrqm/s %wrqm w_await wareq-sz d/s dkB/s drqm/s %drqm d_await dareq-sz aqu-sz %util
		values := make([]float64, 20)
		for i := 0; i < 20; i++ {
			val, err := strconv.ParseFloat(fields[i+1], 64)
			if err != nil {
				return device, fmt.Errorf("failed to parse field %d: %v", i+1, err)
			}
			values[i] = val
		}

		// 旧格式字段映射
		device.ReadReqPerSec = values[0]       // r/s
		device.ReadKBPerSec = values[1]        // rkB/s
		device.ReadMergePerSec = values[2]     // rrqm/s
		device.ReadMergePct = values[3]        // %rrqm
		device.ReadAwait = values[4]           // r_await
		device.ReadReqSize = values[5]         // rareq-sz
		device.WriteReqPerSec = values[6]      // w/s
		device.WriteKBPerSec = values[7]       // wkB/s
		device.WriteMergePerSec = values[8]    // wrqm/s
		device.WriteMergePct = values[9]       // %wrqm
		device.WriteAwait = values[10]         // w_await
		device.WriteReqSize = values[11]       // wareq-sz
		device.DiscardReqPerSec = values[12]   // d/s
		device.DiscardKBPerSec = values[13]    // dkB/s
		device.DiscardMergePerSec = values[14] // drqm/s
		device.DiscardMergePct = values[15]    // %drqm
		device.DiscardAwait = values[16]       // d_await
		device.DiscardReqSize = values[17]     // dareq-sz
		device.AvgQueueSize = values[18]       // aqu-sz
		// device.Utilization = values[19]        // %util

	} else {
		return device, fmt.Errorf("unsupported iostat format: expected 15 or 20 fields, got %d", numFields)
	}

	return device, nil
}

// 查询函数

// GetWriteLatencyTrend 获取指定设备在时间范围内的写延迟趋势
func (log *IOStatLog) GetWriteLatencyTrend(deviceName string, startTime, endTime time.Time) common.TimeValueList {
	var result []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		for _, device := range data.Devices {
			if device.Device == deviceName {
				result = append(result, common.TimeValue{
					Time:  data.Timestamp,
					Value: device.WriteAwait,
				})
				break
			}
		}
	}

	return common.TimeValueList(result)
}

// GetDeviceUtilization 获取设备利用率趋势
// func (log *IOStatLog) GetDeviceUtilization(deviceName string, startTime, endTime time.Time) common.TimeValueList {
// 	var result []common.TimeValue

// 	for _, data := range log.Data {
// 		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
// 			continue
// 		}

// 		for _, device := range data.Devices {
// 			if device.Device == deviceName {
// 				result = append(result, common.TimeValue{
// 					Time:  data.Timestamp,
// 					Value: device.Utilization,
// 				})
// 				break
// 			}
// 		}
// 	}

// 	return common.TimeValueList(result)
// }

// GetIOPSTrend 获取IOPS趋势（读+写请求）
func (log *IOStatLog) GetIOPSTrend(deviceName string, startTime, endTime time.Time) common.TimeValueList {
	var result []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		for _, device := range data.Devices {
			if device.Device == deviceName {
				iops := device.ReadReqPerSec + device.WriteReqPerSec
				result = append(result, common.TimeValue{
					Time:  data.Timestamp,
					Value: iops,
				})
				break
			}
		}
	}

	return common.TimeValueList(result)
}

// GetAllDevices 获取所有设备名称列表
func (log *IOStatLog) GetAllDevices() []string {
	deviceSet := make(map[string]bool)

	for _, data := range log.Data {
		for _, device := range data.Devices {
			deviceSet[device.Device] = true
		}
	}

	var devices []string
	for device := range deviceSet {
		devices = append(devices, device)
	}

	return devices
}

// GetTimeRange 获取数据的时间范围
func (log *IOStatLog) GetTimeRange() (time.Time, time.Time) {
	if len(log.Data) == 0 {
		return time.Time{}, time.Time{}
	}
	return log.Data[0].Timestamp, log.Data[len(log.Data)-1].Timestamp
}

// LatencyStats 延迟统计结构
type LatencyStats struct {
	Mean       float64 // 均值
	StdDev     float64 // 标准差
	Variance   float64 // 方差
	MAD        float64 // 中位绝对偏差
	P50        float64 // 中位数
	P90        float64 // 90百分位
	P95        float64 // 95百分位
	P99        float64 // 99百分位
	Count      int     // 样本数量
	Anomalies  []AnomalyPoint // 异常点
}

// AnomalyPoint 异常点
type AnomalyPoint struct {
	Timestamp time.Time
	Value     float64
	ZScore    float64
	MADScore  float64
	Method    string // 检测方法: "z-score", "iqr", "mad"
}

// GetReadLatencyStats 获取指定设备的读延迟统计分析
func (log *IOStatLog) GetReadLatencyStats(deviceName string, startTime, endTime time.Time) LatencyStats {
	var values []float64
	var timeValues []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		for _, device := range data.Devices {
			if device.Device == deviceName {
				values = append(values, device.ReadAwait)
				timeValues = append(timeValues, common.TimeValue{
					Time:  data.Timestamp,
					Value: device.ReadAwait,
				})
				break
			}
		}
	}

	stats := calculateLatencyStats(values)
	// 执行异常检测，传入设备名称
	stats.Anomalies = detectAnomalies(timeValues, stats, deviceName)
	return stats
}

// GetWriteLatencyStats 获取指定设备的写延迟统计分析
func (log *IOStatLog) GetWriteLatencyStats(deviceName string, startTime, endTime time.Time) LatencyStats {
	var values []float64
	var timeValues []common.TimeValue

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		for _, device := range data.Devices {
			if device.Device == deviceName {
				values = append(values, device.WriteAwait)
				timeValues = append(timeValues, common.TimeValue{
					Time:  data.Timestamp,
					Value: device.WriteAwait,
				})
				break
			}
		}
	}

	stats := calculateLatencyStats(values)
	// 执行异常检测，传入设备名称
	stats.Anomalies = detectAnomalies(timeValues, stats, deviceName)
	return stats
}

// calculateLatencyStats 计算延迟统计信息
func calculateLatencyStats(values []float64) LatencyStats {
	if len(values) == 0 {
		return LatencyStats{}
	}

	stats := LatencyStats{Count: len(values)}

	// 计算均值
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	stats.Mean = sum / float64(len(values))

	// 计算方差和标准差
	sumSquares := 0.0
	for _, v := range values {
		diff := v - stats.Mean
		sumSquares += diff * diff
	}
	stats.Variance = sumSquares / float64(len(values))
	stats.StdDev = math.Sqrt(stats.Variance)

	// 排序后计算百分位和MAD
	sortedValues := make([]float64, len(values))
	copy(sortedValues, values)
	sort.Float64s(sortedValues)

	// 百分位计算
	stats.P50 = calculatePercentile(sortedValues, 50)
	stats.P90 = calculatePercentile(sortedValues, 90)
	stats.P95 = calculatePercentile(sortedValues, 95)
	stats.P99 = calculatePercentile(sortedValues, 99)

	// 计算MAD (中位绝对偏差)
	stats.MAD = calculateMAD(sortedValues, stats.P50)

	// 异常检测 (需要设备名称来确定阈值，这里暂时使用空字符串，实际调用时会传入设备名称)
	stats.Anomalies = []AnomalyPoint{}

	return stats
}

// calculatePercentile 计算百分位数
func calculatePercentile(sortedValues []float64, percentile float64) float64 {
	if len(sortedValues) == 0 {
		return 0
	}

	index := percentile / 100.0 * float64(len(sortedValues)-1)
	lower := int(math.Floor(index))
	upper := int(math.Ceil(index))

	if lower == upper {
		return sortedValues[lower]
	}

	weight := index - float64(lower)
	return sortedValues[lower]*(1-weight) + sortedValues[upper]*weight
}

// calculateMAD 计算中位绝对偏差
func calculateMAD(sortedValues []float64, median float64) float64 {
	deviations := make([]float64, len(sortedValues))
	for i, v := range sortedValues {
		deviations[i] = math.Abs(v - median)
	}
	sort.Float64s(deviations)
	return calculatePercentile(deviations, 50)
}

// getAnomalyThreshold 根据设备类型获取异常检测阈值
func getAnomalyThreshold(deviceName string) float64 {
	// 根据设备名称判断磁盘类型
	if strings.HasPrefix(deviceName, "nvme") {
		return 8.0 // nvme磁盘阈值: 8μs
	} else if strings.HasPrefix(deviceName, "sd") {
		// ssd磁盘或传统机械磁盘(如sda, sdb等)
		return 50.0 // ssd/传统磁盘阈值: 50μs
	}
	// 默认阈值(其他未知设备类型)
	return 8.0
}

// detectAnomalies 异常检测
func detectAnomalies(timeValues []common.TimeValue, stats LatencyStats, deviceName string) []AnomalyPoint {
	var anomalies []AnomalyPoint
	anomalyThreshold := getAnomalyThreshold(deviceName)

	if stats.StdDev == 0 || stats.MAD == 0 {
		return anomalies
	}

	// 计算IQR
	q1 := calculatePercentile(extractValues(timeValues), 25)
	q3 := calculatePercentile(extractValues(timeValues), 75)
	iqr := q3 - q1

	for _, tv := range timeValues {
		value := tv.Value

		// 应用设备类型阈值：如果值小于阈值，不认为是异常
		if value < anomalyThreshold {
			continue
		}

		// Z-score检测
		zScore := math.Abs(value-stats.Mean) / stats.StdDev

		// MAD检测
		madScore := math.Abs(value-stats.P50) / stats.MAD

		// IQR检测
		isIQRAnomaly := value < (q1-1.5*iqr) || value > (q3+1.5*iqr)

		// 判定异常
		method := ""
		if zScore > 3 {
			method = "z-score"
		} else if madScore > 3 {
			method = "mad"
		} else if isIQRAnomaly {
			method = "iqr"
		}

		if method != "" {
			anomalies = append(anomalies, AnomalyPoint{
				Timestamp: tv.Time,
				Value:     value,
				ZScore:    zScore,
				MADScore:  madScore,
				Method:    method,
			})
		}
	}

	return anomalies
}

// extractValues 从TimeValue切片中提取值
func extractValues(timeValues []common.TimeValue) []float64 {
	values := make([]float64, len(timeValues))
	for i, tv := range timeValues {
		values[i] = tv.Value
	}
	sort.Float64s(values)
	return values
}

// GetThroughputStats 获取设备吞吐量统计
func (log *IOStatLog) GetThroughputStats(deviceName string, startTime, endTime time.Time) (readMax, writeMax, readAvg, writeAvg float64) {
	var readValues, writeValues []float64

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		for _, device := range data.Devices {
			if device.Device == deviceName {
				readValues = append(readValues, device.ReadKBPerSec)
				writeValues = append(writeValues, device.WriteKBPerSec)
				break
			}
		}
	}

	if len(readValues) > 0 {
		sort.Float64s(readValues)
		readMax = readValues[len(readValues)-1]
		sum := 0.0
		for _, v := range readValues {
			sum += v
		}
		readAvg = sum / float64(len(readValues))
	}

	if len(writeValues) > 0 {
		sort.Float64s(writeValues)
		writeMax = writeValues[len(writeValues)-1]
		sum := 0.0
		for _, v := range writeValues {
			sum += v
		}
		writeAvg = sum / float64(len(writeValues))
	}

	return
}

// GetAverageQueueDepth 获取平均队列深度
func (log *IOStatLog) GetAverageQueueDepth(deviceName string, startTime, endTime time.Time) float64 {
	var values []float64

	for _, data := range log.Data {
		if data.Timestamp.Before(startTime) || data.Timestamp.After(endTime) {
			continue
		}

		for _, device := range data.Devices {
			if device.Device == deviceName {
				values = append(values, device.AvgQueueSize)
				break
			}
		}
	}

	if len(values) == 0 {
		return 0
	}

	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}
