package lib

type LogType string

const (
	LogTypeLog   LogType = "LOG"
	LogTypeError LogType = "ERROR"
)

type LogEntry struct {
	Type    LogType
	Message string
}
