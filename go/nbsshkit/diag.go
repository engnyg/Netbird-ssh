package NBSSHKit

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
)

const maxLogBytes = 2 << 20

var diagOnce sync.Once

// LogDir is where netbird.log (engine log), crash.log (Go fatal errors of the
// current run) and crash.prev.log (of the previous run) are kept. Reset
// registration does not touch it.
func LogDir(dataDir string) string { return filepath.Join(dataDir, "logs") }

// setupDiagnostics opens the log file and routes Go fatal errors (panics in any
// goroutine) to crash.log, so a crash can be inspected after the app restarts.
// It returns the log file to use as netbird's log output (nil on failure).
func setupDiagnostics(dataDir string) *os.File {
	var logFile *os.File
	diagOnce.Do(func() {
		dir := LogDir(dataDir)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return
		}

		crash := filepath.Join(dir, "crash.log")
		if st, err := os.Stat(crash); err == nil && st.Size() > 0 {
			_ = os.Rename(crash, filepath.Join(dir, "crash.prev.log"))
		}
		if f, err := os.OpenFile(crash, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600); err == nil {
			_ = debug.SetCrashOutput(f, debug.CrashOptions{})
		}

		logPath := filepath.Join(dir, "netbird.log")
		if st, err := os.Stat(logPath); err == nil && st.Size() > maxLogBytes {
			_ = os.Rename(logPath, filepath.Join(dir, "netbird.prev.log"))
		}
		if f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
			logFile = f
		}
	})
	return logFile
}
