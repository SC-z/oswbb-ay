package processor

import internaloutput "oswbb-analyse/internal/output"
import "oswbb-analyse/pkg/diagnosis"

func (fp *FileProcessor) SetOutputSink(s internaloutput.OutputSink) {
	fp.outputSink = s
}

func (fp *FileProcessor) SetDiagnosisProvider(provider diagnosis.Provider) {
	fp.aiService = provider
}

func (fp *FileProcessor) effectiveOutputSink() internaloutput.OutputSink {
	if fp != nil && fp.outputSink != nil {
		return fp.outputSink
	}
	return internaloutput.FileSink{}
}
