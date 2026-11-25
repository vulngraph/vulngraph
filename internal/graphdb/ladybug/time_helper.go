package ladybug

// #include "lbug.h"
// #include <stdlib.h>
import "C"

import (
	"math"
	"time"
)

// unixEpoch returns the Unix epoch time.
func unixEpoch() time.Time {
	return time.Unix(0, 0)
}

// timeToLadybugDate converts a time.Time to a ladybug_date_t.
func timeToLadybugDate(inputTime time.Time) C.lbug_date_t {
	diff := inputTime.Sub(unixEpoch())
	diffDays := math.Floor(diff.Hours() / 24)
	cLadybugDate := C.lbug_date_t{}
	cLadybugDate.days = C.int32_t(diffDays)
	return cLadybugDate
}

// ladybugDateToTime converts a ladybug_date_t to a time.Time in UTC.
func ladybugDateToTime(cLadybugDate C.lbug_date_t) time.Time {
	diff := time.Duration(cLadybugDate.days) * 24 * time.Hour
	return unixEpoch().UTC().Add(diff)
}

// timeToLadybugTimestamp converts a time.Time to a ladybug_timestamp_t.
func timeToLadybugTimestamp(inputTime time.Time) C.lbug_timestamp_t {
	nanoseconds := inputTime.UnixNano()
	microseconds := nanoseconds / 1000
	cLadybugTime := C.lbug_timestamp_t{}
	cLadybugTime.value = C.int64_t(microseconds)
	return cLadybugTime
}

// timeToLadybugTimestampNs converts a time.Time to a ladybug_timestamp_ns_t.
func timeToLadybugTimestampNs(inputTime time.Time) C.lbug_timestamp_ns_t {
	nanoseconds := inputTime.UnixNano()
	cLadybugTime := C.lbug_timestamp_ns_t{}
	cLadybugTime.value = C.int64_t(nanoseconds)
	return cLadybugTime
}

// timeHasNanoseconds returns true if the time.Time has non-zero nanoseconds.
func timeHasNanoseconds(inputTime time.Time) bool {
	return inputTime.Nanosecond() != 0
}

// durationToLadybugInterval converts a time.Duration to a ladybug_interval_t.
func durationToLadybugInterval(inputDuration time.Duration) C.lbug_interval_t {
	microseconds := inputDuration.Microseconds()

	cLadybugInterval := C.lbug_interval_t{}
	cLadybugInterval.micros = C.int64_t(microseconds)
	return cLadybugInterval
}

// ladybugIntervalToDuration converts a ladybug_interval_t to a time.Duration.
func ladybugIntervalToDuration(cLadybugInterval C.lbug_interval_t) time.Duration {
	days := cLadybugInterval.days
	months := cLadybugInterval.months
	microseconds := cLadybugInterval.micros
	totalDays := int64(days) + int64(months)*30
	totalSeconds := totalDays * 24 * 60 * 60
	totalMicroseconds := totalSeconds*1000000 + int64(microseconds)
	totalNanoseconds := totalMicroseconds * 1000
	return time.Duration(totalNanoseconds)
}
