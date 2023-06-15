package main

import "time"

type LogType string

const (
	LogTypeLog   LogType = "LOG"
	LogTypeError LogType = "ERROR"
)

type LogEntry struct {
	Type            LogType
	Message         string
	HostIpAddress   IPAddress
	ClientIpAddress IPAddress
	StartTime       time.Time
	TimeTaken       time.Duration
	StatusCode      int
	BytesWritten    int64
}
