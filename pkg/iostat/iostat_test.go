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
