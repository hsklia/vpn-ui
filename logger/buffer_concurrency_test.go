package logger

import (
	"fmt"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentLogWritersAndWebReaders(t *testing.T) {
	logBufferMu.Lock()
	original := logBuffer
	logBuffer = nil
	logBufferMu.Unlock()
	t.Cleanup(func() { logBufferMu.Lock(); defer logBufferMu.Unlock(); logBuffer = original })
	var workers sync.WaitGroup
	for writer := 0; writer < 8; writer++ {
		workers.Add(1)
		go func(writer int) {
			defer workers.Done()
			for i := 0; i < 1500; i++ {
				addToBuffer("INFO", fmt.Sprintf("packet-log-%d-%d", writer, i))
			}
		}(writer)
	}
	for reader := 0; reader < 4; reader++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 100; i++ {
				for _, entry := range GetLogs(20, "DEBUG") {
					if !strings.Contains(entry, "packet-log-") {
						t.Errorf("corrupted concurrent log entry: %q", entry)
						return
					}
				}
			}
		}()
	}
	workers.Wait()
	logBufferMu.RLock()
	defer logBufferMu.RUnlock()
	if len(logBuffer) != maxLogBufferSize {
		t.Fatalf("buffer grew beyond its limit or lost entries: %d", len(logBuffer))
	}
}
