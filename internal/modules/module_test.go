package modules

import "testing"

func TestModuleNamesRemainStable(t *testing.T) {
	tests := map[ModuleName]string{
		ModuleIostat:  "iostat",
		ModuleMeminfo: "meminfo",
		ModuleTop:     "top",
	}

	for got, want := range tests {
		if string(got) != want {
			t.Fatalf("module name changed: got=%q want=%q", got, want)
		}
	}
}
