package iostat

import (
	"testing"
)

func TestParseDeviceStats_DMDevice(t *testing.T) {
	parser := &IOStatParser{}
	// Sample line mimicking iostat output for a dm device
	// Format: Device r/s w/s rkB/s wkB/s ... (15 fields + 1 device name = 16 fields)
	// Wait, the code says: numFields := len(fields) - 1. If numFields == 15, then len(fields) == 16.
	// dm-0 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00
	line := "dm-0 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00"
	
	device, err := parser.parseDeviceStats(line)
	if err != nil {
		t.Errorf("Expected to parse dm-0 device, but got error: %v", err)
	}
	
	if device.Device != "dm-0" {
		t.Errorf("Expected device name dm-0, got %s", device.Device)
	}
}

func TestParseDeviceStats_MDDevice(t *testing.T) {
	parser := &IOStatParser{}
	// Sample line mimicking iostat output for a md device
	line := "md0 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00 0.00"
	
	_, err := parser.parseDeviceStats(line)
	if err == nil {
		t.Error("Expected error for md0 device, but got nil")
	}
}

func TestParseDeviceStats_HeaderDrivenExtraFields(t *testing.T) {
	parser := &IOStatParser{}

	// 表头包含 f/s 和 f_await 等扩展列（22列数值）
	header := "Device r/s rkB/s rrqm/s %rrqm r_await rareq-sz w/s wkB/s wrqm/s %wrqm w_await wareq-sz d/s dkB/s drqm/s %drqm d_await dareq-sz f/s f_await aqu-sz %util"
	parser.parseDeviceHeader(header)

	// 设备行: 1个设备名 + 22个数值
	line := "nvme0n1 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22"
	device, err := parser.parseDeviceStats(line)
	if err != nil {
		t.Fatalf("header-driven 解析失败: %v", err)
	}

	if device.ReadReqPerSec != 1 || device.ReadKBPerSec != 2 || device.ReadMergePerSec != 3 {
		t.Fatalf("读侧字段映射不正确: %+v", device)
	}
	if device.WriteReqPerSec != 7 || device.WriteKBPerSec != 8 || device.WriteMergePerSec != 9 {
		t.Fatalf("写侧字段映射不正确: %+v", device)
	}
	if device.AvgQueueSize != 21 {
		t.Fatalf("aqu-sz 映射不正确, got %.2f", device.AvgQueueSize)
	}
	if device.AvgReqSize != nil {
		t.Fatalf("表头无 avgrq-sz 时应为 nil, got %+v", device.AvgReqSize)
	}
}
