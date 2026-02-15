package logging

import (
	"context"
	"io"
	"log"
	"log/slog"
	"time"
)

type Handler struct {
	slog.Handler
	logger           *log.Logger
	includeTimestamp bool
}

func NewHandler(writer io.Writer, options *slog.HandlerOptions, includeTimestamp bool) Handler {
	return Handler{
		Handler:          slog.NewTextHandler(writer, options),
		logger:           log.New(writer, "", 0),
		includeTimestamp: includeTimestamp,
	}
}

func (h Handler) Handle(ctx context.Context, r slog.Record) error {
	if h.includeTimestamp {
		h.logger.Printf("[%s %5s] %s", time.Now().Format("2006-01-02_15:04:05"), r.Level.String(), r.Message)
	} else {
		h.logger.Printf("[%5s] %s", r.Level.String(), r.Message)
	}

	return nil
}
