package diff

import (
	"strconv"
	"time"
)

// CycleID returns the default cycle identifier for a run time: the ISO-8601
// year and week, e.g. "2026-W47". Weekly Monday runs therefore get a stable,
// sortable identifier and every run within the same week addresses the same
// cycle (re-running after a failure overwrites atomically rather than
// accumulating duplicate cycles).
func CycleID(now time.Time) string {
	year, week := now.ISOWeek()
	return strconv.Itoa(year) + "-W" + strconv.Itoa(week/10) + strconv.Itoa(week%10)
}
