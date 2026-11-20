package runner

import (
	"encoding/json"
	"testing"
	"time"
)

func mustMarshalJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return data
}

func mustTime(t *testing.T) time.Time {
	t.Helper()
	return time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)
}
