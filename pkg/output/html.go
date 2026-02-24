package output

import (
	"encoding/json"
	"fmt"
	"os"
	"text/template"
)

// HTMLFormatter HTML格式输出器
type HTMLFormatter struct{}

// NewHTMLFormatter 创建HTML输出器
func NewHTMLFormatter() *HTMLFormatter {
	return &HTMLFormatter{}
}

// htmlData 用于传递给模板的数据结构
type htmlData struct {
	Title    string
	DataType string // "iostat" or "meminfo"
	Data     string // JSON string
}

// OutputIOStatData 输出iostat数据为HTML格式
func (f *HTMLFormatter) OutputIOStatData(data []IOStatRawMetrics, filename string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	tmplData := htmlData{
		Title:    "OSWbb IOStat 分析报告",
		DataType: "iostat",
		Data:     string(jsonData),
	}

	return f.writeHTML(filename, tmplData)
}

// OutputMemInfoData 输出meminfo数据为HTML格式
func (f *HTMLFormatter) OutputMemInfoData(data []MemInfoRawMetrics, filename string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	tmplData := htmlData{
		Title:    "OSWbb MemInfo 分析报告",
		DataType: "meminfo",
		Data:     string(jsonData),
	}

	return f.writeHTML(filename, tmplData)
}

// OutputTopData 输出top数据为HTML格式
func (f *HTMLFormatter) OutputTopData(data []TopRawMetrics, filename string) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("JSON序列化失败: %v", err)
	}

	tmplData := htmlData{
		Title:    "OSWbb Top 分析报告",
		DataType: "top",
		Data:     string(jsonData),
	}

	return f.writeHTML(filename, tmplData)
}

func (f *HTMLFormatter) writeHTML(filename string, data htmlData) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建HTML文件失败: %v", err)
	}
	defer file.Close()

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("解析HTML模板失败: %v", err)
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("写入HTML文件失败: %v", err)
	}

	fmt.Printf("已生成交互式HTML报告: %s\n", filename)
	return nil
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <script src="https://cdn.jsdelivr.net/npm/echarts@5.4.3/dist/echarts.min.js"></script>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
        .header { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; position: sticky; top: 0; z-index: 1000; }
        .title { margin: 0 0 15px 0; font-size: 24px; color: #333; }
        .controls { display: flex; gap: 20px; align-items: center; flex-wrap: wrap; }
        .chart-container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; height: 400px; }
        .checkbox-group { display: flex; gap: 10px; flex-wrap: wrap; max-height: 100px; overflow-y: auto; padding: 5px; border: 1px solid #eee; border-radius: 4px; }
        .checkbox-item { display: flex; align-items: center; gap: 4px; font-size: 14px; cursor: pointer; user-select: none; background: #f0f0f0; padding: 2px 8px; border-radius: 12px; }
        .checkbox-item:hover { background: #e0e0e0; }
        .checkbox-item input { margin: 0; }
        .checkbox-item.checked { background: #e3f2fd; color: #1976d2; }
        .btn { padding: 5px 15px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #f5f5f5; }
        .loading { text-align: center; padding: 50px; font-size: 18px; color: #666; }
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">{{.Title}}</h1>
        <div id="controls" class="controls">
            <!-- 动态生成的控件区域 -->
        </div>
    </div>
    <div id="main-container">
        <div class="loading">正在处理数据并渲染图表...</div>
    </div>

    <script>
        // 原始数据
        const rawData = {{.Data}};
        const dataType = "{{.DataType}}";
        
        // ECharts 实例列表
        const charts = [];
        
        // 初始化
        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(() => {
                initDashboard();
            }, 100);
        });

        function initDashboard() {
            const container = document.getElementById('main-container');
            container.innerHTML = ''; // 清除 loading

            if (dataType === 'iostat') {
                renderIOStat(container);
            } else if (dataType === 'meminfo') {
                renderMemInfo(container);
            } else if (dataType === 'top') {
                renderTop(container);
            }
            
            // 窗口大小改变时重绘
            window.addEventListener('resize', () => {
                charts.forEach(chart => chart.resize());
            });
        }

        // ================= IOStat 逻辑 =================
        function renderIOStat(container) {
            // 1. 提取所有设备和时间戳
            const devices = [...new Set(rawData.map(d => d.device))].sort();
            const timestamps = [...new Set(rawData.map(d => d.timestamp))].sort();
            
            // 2. 按设备组织数据: map[device][metric] = []value
            // 预处理为更易查询的结构: map[timestamp][device] = dataObj
            // 但为了 ECharts Series，我们需要 array of values aligned with timestamps
            
            // 定义需要展示的指标
            const metrics = [
                { key: 'read_req_per_sec', name: '读请求/秒 (r/s)' },
                { key: 'write_req_per_sec', name: '写请求/秒 (w/s)' },
                { key: 'read_kb_per_sec', name: '读吞吐量 (KB/s)' },
                { key: 'write_kb_per_sec', name: '写吞吐量 (KB/s)' },
                { key: 'read_await', name: '读延迟 (ms)' },
                { key: 'write_await', name: '写延迟 (ms)' },
                { key: 'avg_queue_size', name: '平均队列深度 (avgqu-sz)' },
                { key: 'avg_req_size', name: '平均请求大小 (avgrq-sz)' },
                { key: 'read_merge_per_sec', name: '读合并/秒 (rrqm/s)' },
                { key: 'write_merge_per_sec', name: '写合并/秒 (wrqm/s)' }
            ];

            // 3. 构建设备筛选控件
            const controlsDiv = document.getElementById('controls');
            
            // 全选/反选按钮
            const btnGroup = document.createElement('div');
            btnGroup.innerHTML = '<button class="btn" onclick="toggleAllDevices(true)">全选</button> <button class="btn" onclick="toggleAllDevices(false)">全不选</button>';
            controlsDiv.appendChild(btnGroup);

            // 设备列表容器
            const devGroup = document.createElement('div');
            devGroup.className = 'checkbox-group';
            devGroup.id = 'device-filters';
            
            // 默认选中的设备（如果设备太多，默认只选前5个防止卡顿）
            const defaultChecked = devices.length > 10 ? devices.slice(0, 5) : devices;
            const checkedDevices = new Set(defaultChecked);

            devices.forEach(dev => {
                const label = document.createElement('label');
                label.className = 'checkbox-item ' + (checkedDevices.has(dev) ? 'checked' : '');
                label.innerHTML = '<input type="checkbox" value="' + dev + '" ' + (checkedDevices.has(dev) ? 'checked' : '') + '> ' + dev;
                
                label.querySelector('input').addEventListener('change', (e) => {
                    if (e.target.checked) {
                        checkedDevices.add(dev);
                        label.classList.add('checked');
                    } else {
                        checkedDevices.delete(dev);
                        label.classList.remove('checked');
                    }
                    updateIOStatCharts(metrics, checkedDevices, timestamps);
                });
                
                devGroup.appendChild(label);
            });
            controlsDiv.appendChild(devGroup);

            // 4. 初始化图表容器
            metrics.forEach(metric => {
                const div = document.createElement('div');
                div.className = 'chart-container';
                div.id = 'chart-' + metric.key;
                container.appendChild(div);
                
                const chart = echarts.init(div);
                chart.group = 'iostat_group'; // 联动分组
                charts.push({ instance: chart, metric: metric });
            });
            
            // 启用联动
            echarts.connect('iostat_group');

            // 5. 首次渲染
            updateIOStatCharts(metrics, checkedDevices, timestamps);
            
            // 导出全局函数供按钮调用
            window.toggleAllDevices = (selectAll) => {
                const inputs = document.querySelectorAll('#device-filters input');
                checkedDevices.clear();
                inputs.forEach(input => {
                    input.checked = selectAll;
                    if (selectAll) {
                        checkedDevices.add(input.value);
                        input.parentElement.classList.add('checked');
                    } else {
                        input.parentElement.classList.remove('checked');
                    }
                });
                updateIOStatCharts(metrics, checkedDevices, timestamps);
            };
        }

        function updateIOStatCharts(metrics, activeDevices, timestamps) {
            // 准备数据缓存：按设备分组
            const deviceDataMap = {}; // device -> { timestamp -> dataObj }
            rawData.forEach(d => {
                if (!deviceDataMap[d.device]) deviceDataMap[d.device] = {};
                deviceDataMap[d.device][d.timestamp] = d;
            });

            charts.forEach(item => {
                const chart = item.instance;
                const metric = item.metric;
                const series = [];

                // 为每个选中的设备生成一条线
                activeDevices.forEach(dev => {
                    // 对齐数据，缺失的时间点补null
                    const data = timestamps.map(ts => {
                        const item = deviceDataMap[dev][ts];
                        return item ? item[metric.key] : null;
                    });

                    series.push({
                        name: dev,
                        type: 'line',
                        showSymbol: false,
                        data: data,
                        smooth: true,
                        emphasis: {
                            focus: 'series' // 高亮当前线，其他变淡
                        }
                    });
                });

                const option = {
                    title: { text: metric.name, left: 'center' },
                    tooltip: {
                        trigger: 'axis',
                        axisPointer: { type: 'cross' }
                    },
                    legend: {
                        data: Array.from(activeDevices),
                        bottom: 0,
                        type: 'scroll'
                    },
                    grid: { left: '3%', right: '4%', bottom: '15%', containLabel: true },
                    xAxis: {
                        type: 'category',
                        data: timestamps,
                        boundaryGap: false
                    },
                    yAxis: { type: 'value' },
                    toolbox: {
                        feature: {
                            dataZoom: { yAxisIndex: 'none' },
                            restore: {}
                        }
                    },
                    dataZoom: [
                        { type: 'slider', show: true, bottom: 35 }
                    ],
                    series: series
                };
                
                chart.setOption(option, true); // true = not merge, completely replace
            });
        }

        // ================= MemInfo 逻辑 =================
        function renderMemInfo(container) {
            const timestamps = rawData.map(d => d.timestamp);
            
            // 定义指标分组
            const metrics = [
                { key: 'mem_total', name: '总内存 (KB)' }, // 通常是直线
                { key: 'mem_available', name: '可用内存 (KB)' },
                { key: 'mem_free', name: '空闲内存 (KB)' },
                { key: 'cached', name: '缓存 (KB)' },
                { key: 'buffers', name: '缓冲区 (KB)' },
                { key: 's_reclaimable', name: 'SReclaimable 可回收 Slab (KB)' },
                { key: 's_unreclaim', name: 'SUnreclaim 不可回收 Slab (KB)' },
                { key: 'anon_pages', name: 'AnonPages 匿名页 (KB)' },
                { key: 'swap_total', name: 'Swap 总量 (KB)' },
                { key: 'swap_free', name: 'Swap 空闲 (KB)' }
            ];
            
            // 内存不需要复杂的设备筛选，直接生成图表
            metrics.forEach(metric => {
                const div = document.createElement('div');
                div.className = 'chart-container';
                div.id = 'chart-' + metric.key;
                container.appendChild(div);
                
                const chart = echarts.init(div);
                chart.group = 'meminfo_group';
                charts.push(chart);
                
                const data = rawData.map(d => d[metric.key]);
                
                const option = {
                    title: { text: metric.name, left: 'center' },
                    tooltip: {
                        trigger: 'axis',
                        formatter: function(params) {
                            // 简单的格式化器，显示值
                            const item = params[0];
                            let val = item.value;
                            // 简单的单位转换显示
                            let valStr = val + ' KB';
                            if (val > 1024*1024) valStr += ' (' + (val/1024/1024).toFixed(2) + ' GB)';
                            else if (val > 1024) valStr += ' (' + (val/1024).toFixed(2) + ' MB)';
                            
                            return item.axisValue + '<br/>' + item.marker + item.seriesName + ': ' + valStr;
                        }
                    },
                    grid: { left: '3%', right: '4%', bottom: '15%', containLabel: true },
                    xAxis: {
                        type: 'category',
                        data: timestamps,
                        boundaryGap: false
                    },
                    yAxis: { type: 'value' },
                    toolbox: {
                        feature: {
                            dataZoom: { yAxisIndex: 'none' },
                            restore: {}
                        }
                    },
                    dataZoom: [
                        { type: 'slider', show: true, bottom: 10 }
                    ],
                    series: [{
                        name: metric.name,
                        type: 'line',
                        showSymbol: false,
                        data: data,
                        smooth: true,
                        areaStyle: { opacity: 0.1 } // 稍微加点面积颜色
                    }]
                };
                
                chart.setOption(option);
            });
            
            echarts.connect('meminfo_group');
        }

        // ================= Top 逻辑 =================
        function renderTop(container) {
            const timestamps = rawData.map(d => d.timestamp);

            // 1. Load Average
            createTopChart(container, 'Load Average', timestamps, [
                { name: 'Load 1min', data: rawData.map(d => d.load_1) },
                { name: 'Load 5min', data: rawData.map(d => d.load_5) },
                { name: 'Load 15min', data: rawData.map(d => d.load_15) }
            ]);

            // 2. CPU Usage
            createTopChart(container, 'CPU 使用率 (%)', timestamps, [
                { name: 'User', data: rawData.map(d => d.cpu_user) },
                { name: 'Sys', data: rawData.map(d => d.cpu_sys) },
                { name: 'Wait', data: rawData.map(d => d.cpu_wait) },
                { name: 'Idle', data: rawData.map(d => d.cpu_idle) }
            ]);

            // 3. Tasks
            createTopChart(container, '进程状态 (Tasks)', timestamps, [
                { name: 'Running', data: rawData.map(d => d.task_running) },
                { name: 'Sleeping', data: rawData.map(d => d.task_sleeping) },
                { name: 'Zombie', data: rawData.map(d => d.task_zombie) }
            ]);
            
            echarts.connect('top_group');
        }

        function createTopChart(container, title, timestamps, seriesData) {
            const div = document.createElement('div');
            div.className = 'chart-container';
            container.appendChild(div);
            
            const chart = echarts.init(div);
            chart.group = 'top_group';
            charts.push(chart);
            
            const series = seriesData.map(s => ({
                name: s.name,
                type: 'line',
                showSymbol: false,
                data: s.data,
                smooth: true
            }));

            const option = {
                title: { text: title, left: 'center' },
                tooltip: { trigger: 'axis' },
                legend: { bottom: 0 },
                grid: { left: '3%', right: '4%', bottom: '10%', containLabel: true },
                xAxis: { type: 'category', data: timestamps, boundaryGap: false },
                yAxis: { type: 'value' },
                dataZoom: [{ type: 'slider', show: true, bottom: 35 }], // 统一使用 slider
                series: series
            };
            chart.setOption(option);
        }
    </script>
</body>
</html>`
