package output

import (
	"bytes"
	"fmt"
	"html/template"
	"oswbb-analyse/internal/report"
)

func (HTMLFormatter) Format(r *report.Report) ([]byte, error) {
	if r == nil {
		return nil, fmt.Errorf("report 不能为空")
	}
	if rawData := r.Metadata["html.raw_data"]; rawData != "" {
		return formatDashboardHTML(r, rawData)
	}
	title := r.Title
	if title == "" {
		title = "OSWbb Analyse Report"
	}
	data := struct {
		Title  string
		Report *report.Report
	}{
		Title:  title,
		Report: r,
	}

	tmpl, err := template.New("report").Parse(reportHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("解析HTML模板失败: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("渲染HTML失败: %v", err)
	}
	return buf.Bytes(), nil
}

type dashboardHTMLData struct {
	Title            string
	DataType         string
	Data             template.JS
	Findings         []report.Finding
	ShowFindings     bool
	ShowAI           bool
	AIStatus         string
	AISummary        string
	AIFallbackReason string
	Suggestions      []report.Suggestion
}

func formatDashboardHTML(r *report.Report, rawData string) ([]byte, error) {
	title := r.Title
	if title == "" {
		title = "OSWbb Analyse Report"
	}
	data := dashboardHTMLData{
		Title:            title,
		DataType:         r.Metadata["html.data_type"],
		Data:             template.JS(rawData),
		Findings:         r.Findings,
		ShowFindings:     len(r.Findings) > 0,
		ShowAI:           r.Metadata["ai.enabled"] == "true" || len(r.Suggestions) > 0,
		AIStatus:         r.Metadata["ai.status"],
		AISummary:        r.Metadata["ai.summary"],
		AIFallbackReason: r.Metadata["ai.fallback_reason"],
		Suggestions:      r.Suggestions,
	}
	if data.AISummary == "" && len(r.Suggestions) > 0 {
		data.AISummary = "AI 辅助诊断已生成建议核查项。"
	}

	tmpl, err := template.New("dashboard").Parse(dashboardHTMLTemplate)
	if err != nil {
		return nil, fmt.Errorf("解析HTML模板失败: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("渲染HTML失败: %v", err)
	}
	return buf.Bytes(), nil
}

const reportHTMLTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #243142; }
        .header, .report-section, .report-table, .ai-summary, .diagnosis-panel { background: white; padding: 18px 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.08); margin-bottom: 20px; }
        .title { margin: 0; font-size: 24px; color: #333; }
        .summary-list { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px 18px; margin: 14px 0 0; padding: 0; list-style: none; }
        .summary-list li { color: #334155; }
        .summary-name { font-weight: 600; color: #26364a; }
        .report-section h2, .report-table h2, .ai-summary h2 { margin: 0 0 10px 0; font-size: 18px; color: #26364a; }
        .section-body { white-space: pre-wrap; line-height: 1.55; }
        table { width: 100%; border-collapse: collapse; background: white; }
        th, td { border: 1px solid #dbe4ee; padding: 7px 9px; text-align: left; vertical-align: top; }
        th { background: #f1f5f9; color: #26364a; }
        .findings-summary { padding: 0; border: 0; background: transparent; }
        .findings-summary summary { cursor: pointer; font-size: 18px; font-weight: 600; color: #26364a; list-style: none; }
        .findings-summary summary::-webkit-details-marker { display: none; }
        .findings-summary summary::after { content: "展开"; float: right; font-size: 13px; font-weight: 500; color: #5b6472; }
        .findings-summary[open] summary::after { content: "收起"; }
        .finding-list { margin: 12px 0 0; padding-left: 18px; }
        .finding-list li { margin-bottom: 12px; }
        .finding-badge { display: inline-block; padding: 2px 7px; border-radius: 999px; font-size: 12px; line-height: 1.4; background: #e9eef5; color: #28384c; margin-right: 6px; }
        .finding-meta, .suggestion-detail { margin-top: 4px; font-size: 13px; color: #5b6472; }
        .finding-detail { margin-top: 4px; color: #334155; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="header">
        <h1 class="title">{{.Title}}</h1>
        {{if .Report.Summary}}
        <ul class="summary-list">
            {{range .Report.Summary}}
            <li><span class="summary-name">{{.Name}}:</span> {{.Value}}</li>
            {{end}}
        </ul>
        {{end}}
    </div>

    {{if .Report.Metadata}}
    <section class="report-section">
        <h2>元数据</h2>
        <table>
            <tbody>
                {{range $name, $value := .Report.Metadata}}<tr><th>{{$name}}</th><td>{{$value}}</td></tr>{{end}}
            </tbody>
        </table>
    </section>
    {{end}}

    {{if .Report.Findings}}
    <section class="diagnosis-panel">
        <details class="findings-summary">
            <summary>规则诊断摘要</summary>
            <ul class="finding-list">
                {{range .Report.Findings}}
                <li>
                    {{if .Severity}}<span class="finding-badge">{{.Severity}}</span>{{end}}
                    {{if .Nature}}<span class="finding-badge">{{.Nature}}</span>{{end}}
                    <strong>{{.Title}}</strong>
                    {{if .Evidence}}<div class="finding-meta">{{.Evidence}}</div>{{end}}
                    {{if .Detail}}<div class="finding-detail">{{.Detail}}</div>{{end}}
                </li>
                {{end}}
            </ul>
        </details>
    </section>
    {{end}}

    {{range .Report.Sections}}
    <section class="report-section">
        {{if .Title}}<h2>{{.Title}}</h2>{{end}}
        {{if .Body}}<div class="section-body">{{.Body}}</div>{{end}}
    </section>
    {{end}}

    {{range .Report.Tables}}
    <section class="report-table">
        {{if .Title}}<h2>{{.Title}}</h2>{{end}}
        <table>
            {{if .Headers}}
            <thead><tr>{{range .Headers}}<th>{{.}}</th>{{end}}</tr></thead>
            {{end}}
            <tbody>
                {{range .Rows}}<tr>{{range .}}<td>{{.}}</td>{{end}}</tr>{{end}}
            </tbody>
        </table>
    </section>
    {{end}}

    {{if .Report.Suggestions}}
    <section class="ai-summary">
        <h2>建议核查</h2>
        <ul>
            {{range .Report.Suggestions}}
            <li><strong>{{.Title}}</strong>{{if .Detail}}<div class="suggestion-detail">{{.Detail}}</div>{{end}}</li>
            {{end}}
        </ul>
    </section>
    {{end}}
</body>
</html>
`

const dashboardHTMLTemplate = `<!DOCTYPE html>
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
        .ai-summary { margin-top: 16px; padding: 16px 18px; border-radius: 10px; background: linear-gradient(135deg, #f5fbff, #eef7ff); border: 1px solid #d6e8fb; }
        .ai-summary.fallback { background: linear-gradient(135deg, #fff8ed, #fff2d8); border-color: #f0c77a; }
        .ai-summary h2 { margin: 0 0 10px 0; font-size: 18px; color: #214c74; }
        .ai-summary.fallback h2 { color: #8a5a09; }
        .ai-summary p { margin: 8px 0; color: #334155; line-height: 1.5; }
        .diagnosis-panel { margin-bottom: 20px; }
        .findings-summary { padding: 14px 18px; border-radius: 10px; background: #fbfcfe; border: 1px solid #dbe4ee; }
        .findings-summary summary { cursor: pointer; font-size: 18px; font-weight: 600; color: #26364a; list-style: none; }
        .findings-summary summary::-webkit-details-marker { display: none; }
        .findings-summary summary::after { content: "展开"; float: right; font-size: 13px; font-weight: 500; color: #5b6472; }
        .findings-summary[open] summary::after { content: "收起"; }
        .finding-list { margin: 12px 0 0; padding-left: 18px; }
        .finding-list li { margin-bottom: 12px; color: #243142; }
        .finding-badges { display: inline-flex; gap: 6px; margin-right: 6px; vertical-align: middle; }
        .finding-badge { display: inline-block; padding: 2px 7px; border-radius: 999px; font-size: 12px; line-height: 1.4; background: #e9eef5; color: #28384c; }
        .finding-meta { margin-top: 4px; font-size: 13px; color: #5b6472; }
        .finding-summary { margin-top: 4px; color: #334155; line-height: 1.5; }
        .incident-list { margin: 12px 0 0 0; padding-left: 18px; }
        .incident-list li { margin-bottom: 10px; color: #243b53; }
        .incident-checks { margin-top: 4px; font-size: 13px; color: #475569; }
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
        <div id="controls" class="controls"></div>
        {{if .ShowAI}}
        <div class="ai-summary {{if eq .AIStatus "fallback"}}fallback{{end}}">
            <h2>AI 辅助诊断</h2>
            {{if eq .AIStatus "fallback"}}
            <p>AI 诊断未生效，已回退到规则分析：{{.AIFallbackReason}}</p>
            {{else}}
            <p>{{.AISummary}}</p>
            {{if .Suggestions}}
            <ul class="incident-list">
                {{range .Suggestions}}
                <li><strong>{{.Title}}</strong>{{if .Detail}}<div class="incident-checks">建议核查: {{.Detail}}</div>{{end}}</li>
                {{end}}
            </ul>
            {{else}}
            <p>模型本次未补充出新的高置信 incident。</p>
            {{end}}
            {{end}}
        </div>
        {{end}}
    </div>
    {{if .ShowFindings}}
    <section class="diagnosis-panel">
        <details class="findings-summary">
            <summary>规则诊断摘要</summary>
            <ul class="finding-list">
                {{range .Findings}}
                <li>
                    <span class="finding-badges">
                        {{if .Severity}}<span class="finding-badge">{{.Severity}}</span>{{end}}
                        {{if .Nature}}<span class="finding-badge">{{.Nature}}</span>{{end}}
                    </span>
                    <strong>{{.Title}}</strong>
                    {{if .Evidence}}<div class="finding-meta">{{.Evidence}}</div>{{end}}
                    {{if .Detail}}<div class="finding-summary">{{.Detail}}</div>{{end}}
                </li>
                {{end}}
            </ul>
        </details>
    </section>
    {{end}}
    <div id="main-container">
        <div class="loading">正在处理数据并渲染图表...</div>
    </div>

    <script>
        const rawData = {{.Data}};
        const dataType = "{{.DataType}}";
        const charts = [];

        document.addEventListener('DOMContentLoaded', () => {
            setTimeout(() => {
                initDashboard();
            }, 100);
        });

        function initDashboard() {
            const container = document.getElementById('main-container');
            container.innerHTML = '';

            if (dataType === 'iostat') {
                renderIOStat(container);
            } else if (dataType === 'meminfo') {
                renderMemInfo(container);
            } else if (dataType === 'top') {
                renderTop(container);
			}

			window.addEventListener('resize', () => {
				charts.forEach(chart => {
					if (chart.resize) chart.resize();
					else if (chart.instance) chart.instance.resize();
				});
			});
		}

        function renderIOStat(container) {
            const devices = [...new Set(rawData.map(d => d.device))].sort();
            const timestamps = [...new Set(rawData.map(d => d.timestamp))].sort();
            const metrics = [
                { key: 'read_req_per_sec', name: '读请求/秒 (r/s)' },
                { key: 'write_req_per_sec', name: '写请求/秒 (w/s)' },
                { key: 'read_kb_per_sec', name: '读吞吐量 (KB/s)' },
                { key: 'write_kb_per_sec', name: '写吞吐量 (KB/s)' },
                { key: 'read_await', name: '读延迟 (ms)' },
                { key: 'write_await', name: '写延迟 (ms)' },
                { key: 'avg_queue_size', name: '平均队列深度 (avgqu-sz)' },
                { key: 'utilization', name: '设备利用率 (%)' },
                { key: 'avg_req_size', name: '平均请求大小 (avgrq-sz)' },
                { key: 'read_merge_per_sec', name: '读合并/秒 (rrqm/s)' },
                { key: 'write_merge_per_sec', name: '写合并/秒 (wrqm/s)' }
            ];
            const controlsDiv = document.getElementById('controls');
            const btnGroup = document.createElement('div');
            btnGroup.innerHTML = '<button class="btn" onclick="toggleAllDevices(true)">全选</button> <button class="btn" onclick="toggleAllDevices(false)">全不选</button>';
            controlsDiv.appendChild(btnGroup);

            const devGroup = document.createElement('div');
            devGroup.className = 'checkbox-group';
            devGroup.id = 'device-filters';
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

            metrics.forEach(metric => {
                const div = document.createElement('div');
                div.className = 'chart-container';
                div.id = 'chart-' + metric.key;
                container.appendChild(div);
                const chart = echarts.init(div);
                chart.group = 'iostat_group';
                charts.push({ instance: chart, metric: metric });
            });
            echarts.connect('iostat_group');
            updateIOStatCharts(metrics, checkedDevices, timestamps);

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
            const deviceDataMap = {};
            rawData.forEach(d => {
                if (!deviceDataMap[d.device]) deviceDataMap[d.device] = {};
                deviceDataMap[d.device][d.timestamp] = d;
            });

			charts.forEach(item => {
				const series = [];
				activeDevices.forEach(dev => {
					series.push({
						name: dev,
						type: 'line',
                        showSymbol: false,
                        data: timestamps.map(ts => {
                            const row = deviceDataMap[dev][ts];
                            return row ? row[item.metric.key] : null;
                        }),
                        smooth: true,
                        emphasis: { focus: 'series' }
                    });
                });

                item.instance.setOption({
                    title: { text: item.metric.name, left: 'center' },
                    tooltip: { trigger: 'axis', axisPointer: { type: 'cross' } },
                    legend: { data: Array.from(activeDevices), bottom: 0, type: 'scroll' },
                    grid: { left: '3%', right: '4%', bottom: '15%', containLabel: true },
                    xAxis: { type: 'category', data: timestamps, boundaryGap: false },
                    yAxis: { type: 'value' },
                    toolbox: { feature: { dataZoom: { yAxisIndex: 'none' }, restore: {} } },
                    dataZoom: [{ type: 'slider', show: true, bottom: 35 }],
                    series: series
                }, true);
            });
        }

        function renderMemInfo(container) {
            const timestamps = rawData.map(d => d.timestamp);
            const metrics = [
                { key: 'mem_total', name: '总内存 (KB)' },
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
            metrics.forEach(metric => {
                const div = document.createElement('div');
                div.className = 'chart-container';
                div.id = 'chart-' + metric.key;
                container.appendChild(div);
                const chart = echarts.init(div);
                chart.group = 'meminfo_group';
                charts.push(chart);
                chart.setOption({
                    title: { text: metric.name, left: 'center' },
                    tooltip: {
                        trigger: 'axis',
                        formatter: function(params) {
                            const item = params[0];
                            let val = item.value;
                            let valStr = val + ' KB';
                            if (val > 1024*1024) valStr += ' (' + (val/1024/1024).toFixed(2) + ' GB)';
                            else if (val > 1024) valStr += ' (' + (val/1024).toFixed(2) + ' MB)';
                            return item.axisValue + '<br/>' + item.marker + item.seriesName + ': ' + valStr;
                        }
                    },
                    grid: { left: '3%', right: '4%', bottom: '15%', containLabel: true },
                    xAxis: { type: 'category', data: timestamps, boundaryGap: false },
                    yAxis: { type: 'value' },
                    toolbox: { feature: { dataZoom: { yAxisIndex: 'none' }, restore: {} } },
                    dataZoom: [{ type: 'slider', show: true, bottom: 10 }],
                    series: [{ name: metric.name, type: 'line', showSymbol: false, data: rawData.map(d => d[metric.key]), smooth: true, areaStyle: { opacity: 0.1 } }]
                });
            });
            echarts.connect('meminfo_group');
        }

        function renderTop(container) {
            const timestamps = rawData.map(d => d.timestamp);
            createTopChart(container, 'Load Average', timestamps, [
                { name: 'Load 1min', data: rawData.map(d => d.load_1) },
                { name: 'Load 5min', data: rawData.map(d => d.load_5) },
                { name: 'Load 15min', data: rawData.map(d => d.load_15) }
            ]);
            createTopChart(container, 'CPU 使用率 (%)', timestamps, [
                { name: 'User', data: rawData.map(d => d.cpu_user) },
                { name: 'Sys', data: rawData.map(d => d.cpu_sys) },
                { name: 'Wait', data: rawData.map(d => d.cpu_wait) },
                { name: 'Idle', data: rawData.map(d => d.cpu_idle) }
            ]);
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
            chart.setOption({
                title: { text: title, left: 'center' },
                tooltip: { trigger: 'axis' },
                legend: { bottom: 0 },
                grid: { left: '3%', right: '4%', bottom: '10%', containLabel: true },
                xAxis: { type: 'category', data: timestamps, boundaryGap: false },
                yAxis: { type: 'value' },
                dataZoom: [{ type: 'slider', show: true, bottom: 35 }],
                series: seriesData.map(s => ({ name: s.name, type: 'line', showSymbol: false, data: s.data, smooth: true }))
            });
        }
    </script>
</body>
</html>`
