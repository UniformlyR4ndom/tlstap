package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

type Logger struct {
	logger *slog.Logger
}

func NewLogger(writer io.Writer, options *slog.HandlerOptions) Logger {
	return Logger{
		logger: slog.New(NewHandler(writer, options)),
	}
}

func (l *Logger) Fatal(msgFmt string, args ...any) {
	l.logger.Error(fmt.Sprintf(msgFmt, args...))
	os.Exit(1)
}

func (l *Logger) Error(msgFmt string, args ...any) {
	l.logger.Error(fmt.Sprintf(msgFmt, args...))
}

func (l *Logger) Warn(msgFmt string, args ...any) {
	l.logger.Warn(fmt.Sprintf(msgFmt, args...))
}

func (l *Logger) Info(msgFmt string, args ...any) {
	l.logger.Info(fmt.Sprintf(msgFmt, args...))
}

func (l *Logger) Debug(msgFmt string, args ...any) {
	l.logger.Debug(fmt.Sprintf(msgFmt, args...))
}
