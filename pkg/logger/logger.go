package logger

import (
	"io"
	"os"
	"strings"

	"github.com/enterprise/distributed-health-monitor/internal/config"
	"github.com/sirupsen/logrus"
	"gopkg.in/natefinch/lumberjack.v2"
)

// New creates a new logger instance based on configuration
func New(cfg config.LoggingConfig) *logrus.Logger {
	logger := logrus.New()

	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)

	// Set log format
	switch strings.ToLower(cfg.Format) {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	default:
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	}

	// Set output
	var output io.Writer
	switch strings.ToLower(cfg.Output) {
	case "stdout":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		if cfg.FileRotation {
			output = &lumberjack.Logger{
				Filename:   cfg.Output,
				MaxSize:    cfg.MaxSize,    // megabytes
				MaxBackups: cfg.MaxBackups,
				MaxAge:     cfg.MaxAge,     // days
				Compress:   true,
			}
		} else {
			file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				output = os.Stdout
			} else {
				output = file
			}
		}
	}

	logger.SetOutput(output)

	return logger
}
