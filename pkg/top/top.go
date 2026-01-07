package top

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// TopParser 解析器
type TopParser struct{}

// NewTopParser 创��新的解析器
func NewTopParser() *TopParser {
	return &TopParser{}
}

// ParseFile 解析top文件
func (p *TopParser) ParseFile(filename string) (*TopLog, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	log := &TopLog{
		Snapshots: make([]TopSnapshot, 0),
	}

	scanner := bufio.NewScanner(file)
	var currentSnapshot *TopSnapshot

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "zzz ***") {
			// 如果当前有快照数据，保存它
			// 注意：这里我们假设只要有时间戳，就是一个新快照的开始
			// 如果前一个快照完全没解析到数据（比如只有时间戳），保留它还是丢弃？
			// 鉴于OSWatcher的特性，建议保留，但目前结构体默认值都是0
			if currentSnapshot != nil {
				log.Snapshots = append(log.Snapshots, *currentSnapshot)
			}

			// 解析时间戳
			timestamp, err := p.parseTimestamp(line)
			if err != nil {
				// 如果时间戳解析失败，重置当前快照，避免数据混淆
				currentSnapshot = nil
				continue
			}

			// 创建新快照
			currentSnapshot = &TopSnapshot{
				Timestamp: timestamp,
			}
			continue
		}

		// 如果没有��前快照上下文，跳过后续解析
		if currentSnapshot == nil {
			continue
		}

		// 解析 Load Average
		// 格式: top - 09:00:09 up 927 days, 20:58,  0 users,  load average: 24.01, 25.49, 25.36
		if strings.Contains(line, "load average:") {
			p.parseLoadAverage(line, currentSnapshot)
			continue
		}

		// 解析 Tasks
		// 格式: Tasks: 3277 total,  30 running, 3247 sleeping,   0 stopped,   0 zombie
		if strings.HasPrefix(line, "Tasks:") {
			p.parseTasks(line, currentSnapshot)
			continue
		}

		// 解析 CPU
		// 格式: %Cpu(s): 16.5 us,  2.7 sy,  0.0 ni, 80.1 id,  0.2 wa,  0.0 hi,  0.6 si,  0.0 st
		if strings.HasPrefix(line, "%Cpu(s):") || strings.HasPrefix(line, "Cpu(s):") {
			p.parseCpu(line, currentSnapshot)
			continue
		}
	}

	// 添加最后一个快照
	if currentSnapshot != nil {
		log.Snapshots = append(log.Snapshots, *currentSnapshot)
	}

	return log, scanner.Err()
}

// parseTimestamp 解析时间戳
// 格式: zzz ***Wed Dec 17 09:00:02 CST 2025
func (p *TopParser) parseTimestamp(line string) (time.Time, error) {
	// 移除 "zzz ***" 前缀
	// 注意：有些版本可能是 "zzz ***Wed" (紧凑) 或 "zzz *** Wed" (有空格)
	// 简单策略：找到第一个 "*" 后的内容，或者按空格分割
	
	parts := strings.Fields(line)
	// parts 可能是 ["zzz", "***Wed", "Dec", "17", "09:00:02", "CST", "2025"]
	// 或者是 ["zzz", "***", "Wed", "Dec", "17", ...]
	
	if len(parts) < 6 {
		return time.Time{}, fmt.Errorf("invalid timestamp line")
	}

	// 寻找月份字段的位置，通常是 Dec, Jan 等
	// 简单处理：取最后5个部分拼接 "Dec 17 09:00:02 CST 2025"
	if len(parts) >= 5 {
		timeParts := parts[len(parts)-5:]
		timeStr := strings.Join(timeParts, " ")
		layout := "Jan 2 15:04:05 MST 2006"
		
		parsedTime, err := time.Parse(layout, timeStr)
		if err != nil {
			return time.Time{}, err
		}
		
		// 转换为CST时区 (OSWatcher通常记录本地时间，这里强制指定CST以保持一致性)
		cst := time.FixedZone("CST", 8*3600)
		return parsedTime.In(cst), nil
	}

	return time.Time{}, fmt.Errorf("unknown timestamp format")
}

// parseLoadAverage 解析负载
func (p *TopParser) parseLoadAverage(line string, snap *TopSnapshot) {
	idx := strings.Index(line, "load average:")
	if idx == -1 {
		return
	}
	
	loadStr := line[idx+len("load average:"):]
	// 24.01, 25.49, 25.36
	loadStr = strings.TrimSpace(loadStr)
	parts := strings.Split(loadStr, ",")
	
	if len(parts) >= 3 {
		fmt.Sscanf(parts[0], "%f", &snap.Load1)
		fmt.Sscanf(parts[1], "%f", &snap.Load5)
		fmt.Sscanf(parts[2], "%f", &snap.Load15)
	}
}

// parseTasks 解析任务状态
func (p *TopParser) parseTasks(line string, snap *TopSnapshot) {
	// Tasks: 3277 total,  30 running, 3247 sleeping,   0 stopped,   0 zombie
	// 移除 "Tasks:"
	content := strings.TrimPrefix(line, "Tasks:")
	content = strings.TrimSpace(content)
	
	// 使用 Sscanf 直接匹配
	// 注意：格式必须严格匹配，包括逗号
	// 为了兼容性，先替换逗号为空格，再 Scan
	cleanLine := strings.ReplaceAll(content, ",", "")
	
	var total, running, sleeping, stopped, zombie int
	// 尝试匹配标准格式
	_, err := fmt.Sscanf(cleanLine, "%d total %d running %d sleeping %d stopped %d zombie", 
		&total, &running, &sleeping, &stopped, &zombie)
		
	if err == nil {
		snap.TaskTotal = total
		snap.TaskRunning = running
		snap.TaskSleeping = sleeping
		snap.TaskStopped = stopped
		snap.TaskZombie = zombie
	}
}

// parseCpu 解析CPU使用率
func (p *TopParser) parseCpu(line string, snap *TopSnapshot) {
	// %Cpu(s): 16.5 us,  2.7 sy,  0.0 ni, 80.1 id,  0.2 wa,  0.0 hi,  0.6 si,  0.0 st
	// 移除前缀
	idx := strings.Index(line, ":")
	if idx == -1 {
		return
	}
	content := line[idx+1:]
	
	// 同样，移除逗号以便处理
	cleanLine := strings.ReplaceAll(content, ",", "")
	
	// fmt.Sscanf 需要格式完全匹配，但这里每个字段都有后缀
	// 我们可以循环读取
	parts := strings.Fields(cleanLine)
	for i := 0; i < len(parts)-1; i += 2 {
		valStr := parts[i]
		key := parts[i+1]
		
		var val float64
		fmt.Sscanf(valStr, "%f", &val)
		
		switch key {
		case "us":
			snap.CpuUser = val
		case "sy":
			snap.CpuSys = val
		case "ni":
			snap.CpuNice = val
		case "id":
			snap.CpuIdle = val
		case "wa":
			snap.CpuWait = val
		case "hi":
			snap.CpuHi = val
		case "si":
			snap.CpuSi = val
		case "st":
			snap.CpuSteal = val
		}
	}
}
