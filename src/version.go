package main

import (
	"strconv"
	"time"
)

// Build information is set by linker flags; BuildDate is derived from BuildEpoch.
var (
	Version      = "devel"
	CommitID     = "N/A"
	BuildDate    = "N/A"
	BuildEpoch   = "0"
	OfficialSite = ""
)

func init() {
	BuildDate = buildDateFromEpoch(BuildEpoch)
}

func buildDateFromEpoch(epoch string) string {
	seconds, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil || seconds <= 0 {
		return "N/A"
	}
	return time.Unix(seconds, 0).UTC().Format("2006-01-02T15:04:05Z")
}
