package logging

import (
	"context"
	"io"
	"log"
	"log/slog"
)

type Handler struct {
	slog.Handler
	logger *log.Logger
}

func NewHandler(writer io.Writer, options *slog.HandlerOptions) Handler {
	return Handler{
		Handler: slog.NewTextHandler(writer, options),
		logger:  log.New(writer, "", 0),
	}
}

func (h Handler) Handle(ctx context.Context, r slog.Record) error {
	h.logger.Printf("%s: %s", r.Level.String(), r.Message)
	return nil
}
