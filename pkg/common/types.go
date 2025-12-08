package common

import "time"

// TimeValue 时间-数值对
type TimeValue struct {
	Time  time.Time
	Value float64
}

// TimeValueList 时间-数值列表类型
type TimeValueList []TimeValue

// TrendAnomaly 记录检测到的趋势异常
type TrendAnomaly struct {
	Type      string    // 异常类型 (e.g., "骤升", "骤降")
	Time      time.Time // 异常发生时间
	Value     float64   // 异常值/变化量 (绝对值)
	IsSudden  bool      // 是否为单点骤变
	
	// 详情字段
	StartVal  float64   // 变化前的值
	EndVal    float64   // 变化后的值
	Threshold float64   // 判定阈值
	RuleName  string    // 命中规则名称
}

// 统计函数
func (tv TimeValueList) Average() float64 {
	if len(tv) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range tv {
		sum += v.Value
	}
	return sum / float64(len(tv))
}

func (tv TimeValueList) Max() TimeValue {
	if len(tv) == 0 {
		return TimeValue{}
	}

	max := tv[0].Value
	maxTime := tv[0].Time
	for _, v := range tv {
		if v.Value > max {
			max = v.Value
			maxTime = v.Time
		}
	}
	return TimeValue{Time: maxTime, Value: max}
}

func (tv TimeValueList) Min() TimeValue {
	if len(tv) == 0 {
		return TimeValue{}
	}

	min := tv[0].Value
	minTime := tv[0].Time
	for _, v := range tv {
		if v.Value < min {
			min = v.Value
			minTime = v.Time
		}
	}
	return TimeValue{Time: minTime, Value: min}
}
