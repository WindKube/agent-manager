package worker

import (
	"context"
	"log/slog"
	"slices"
	"strings"

	"github.com/rs/zerolog"
)

// River logs through slog and this project logs through zerolog. Bridging them
// here keeps one structured format on stdout; the alternative is two JSON shapes
// interleaved in the same stream, which makes the observability requirement
// (structured logs with a job correlation id) a lie in practice.
func slogFrom(log zerolog.Logger) *slog.Logger {
	return slog.New(&zerologHandler{log: log})
}

type zerologHandler struct {
	log    zerolog.Logger
	groups []string
	attrs  []slog.Attr
}

func (h *zerologHandler) Enabled(_ context.Context, level slog.Level) bool {
	return zerologLevel(level) >= h.log.GetLevel()
}

func (h *zerologHandler) Handle(_ context.Context, rec slog.Record) error {
	event := h.log.WithLevel(zerologLevel(rec.Level))
	for _, attr := range h.attrs {
		appendAttr(event, h.groups, attr)
	}
	rec.Attrs(func(attr slog.Attr) bool {
		appendAttr(event, h.groups, attr)
		return true
	})
	event.Msg(rec.Message)
	return nil
}

func (h *zerologHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(slices.Clone(h.attrs), attrs...)
	return &next
}

func (h *zerologHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.groups = append(slices.Clone(h.groups), name)
	return &next
}

// appendAttr flattens a group into a dotted key, because zerolog's event API has
// no nesting that survives the JSON encoder without buffering.
func appendAttr(event *zerolog.Event, groups []string, attr slog.Attr) {
	value := attr.Value.Resolve()
	if value.Kind() == slog.KindGroup {
		inner := append(slices.Clone(groups), attr.Key)
		for _, nested := range value.Group() {
			appendAttr(event, inner, nested)
		}
		return
	}
	key := attr.Key
	if len(groups) > 0 {
		key = strings.Join(groups, ".") + "." + key
	}
	event.Any(key, value.Any())
}

func zerologLevel(level slog.Level) zerolog.Level {
	switch {
	case level < slog.LevelInfo:
		return zerolog.DebugLevel
	case level < slog.LevelWarn:
		return zerolog.InfoLevel
	case level < slog.LevelError:
		return zerolog.WarnLevel
	default:
		return zerolog.ErrorLevel
	}
}
