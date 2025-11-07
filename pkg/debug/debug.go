package debug

import (
	"context"
	"flag"
	"log/slog"
	"os"
)

const (
	DEBUG_CRITICAL = 1
	DEBUG_ERROR    = 2
	DEBUG_INFO     = 3
	DEBUG_VERBOSE  = 4
	DEBUG_TRACE    = 5
	DEBUG_PACKETS  = 6
	DEBUG_ALL      = 7
)

var (
	debugLevel = flag.Int("debug", 3, "debug level (1-7)")
	logger     *slog.Logger
	initialized bool
)

func Init() {
	if initialized {
		return
	}
	initialized = true

	var level slog.Level
	switch {
	case *debugLevel >= DEBUG_ALL:
		level = slog.LevelDebug
	case *debugLevel >= DEBUG_PACKETS:
		level = slog.LevelDebug
	case *debugLevel >= DEBUG_TRACE:
		level = slog.LevelDebug
	case *debugLevel >= DEBUG_VERBOSE:
		level = slog.LevelDebug
	case *debugLevel >= DEBUG_INFO:
		level = slog.LevelInfo
	case *debugLevel >= DEBUG_ERROR:
		level = slog.LevelWarn
	case *debugLevel >= DEBUG_CRITICAL:
		level = slog.LevelError
	default:
		level = slog.LevelError
	}

	opts := &slog.HandlerOptions{
		Level: level,
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, opts))
	slog.SetDefault(logger)
}

func GetLogger() *slog.Logger {
	if !initialized {
		Init()
	}
	return logger
}

func Log(level int, msg string, args ...interface{}) {
	if !initialized {
		Init()
	}

	if *debugLevel < level {
		return
	}

	var slogLevel slog.Level
	switch {
	case level >= DEBUG_ALL:
		slogLevel = slog.LevelDebug
	case level >= DEBUG_PACKETS:
		slogLevel = slog.LevelDebug
	case level >= DEBUG_TRACE:
		slogLevel = slog.LevelDebug
	case level >= DEBUG_VERBOSE:
		slogLevel = slog.LevelDebug
	case level >= DEBUG_INFO:
		slogLevel = slog.LevelInfo
	case level >= DEBUG_ERROR:
		slogLevel = slog.LevelWarn
	case level >= DEBUG_CRITICAL:
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelError
	}

	if !logger.Enabled(context.TODO(), slogLevel) {
		return
	}

	allArgs := make([]interface{}, len(args)+2)
	copy(allArgs, args)
	allArgs[len(args)] = "debug_level"
	allArgs[len(args)+1] = level
	logger.Log(context.TODO(), slogLevel, msg, allArgs...)
}

func SetDebugLevel(level int) {
	*debugLevel = level
	if initialized {
		Init()
	}
}

func GetDebugLevel() int {
	return *debugLevel
}

