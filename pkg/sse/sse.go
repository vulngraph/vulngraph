// Package sse is the server side of the streaming-response protocol the chat
// and decision-refine endpoints share: {"type":"text","text":…} deltas, then
// exactly one terminal {"type":"done"} or {"type":"error","message":…}. A
// stream without a terminal event was cut, and clients treat it as a failure.
package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// ExtendWriteDeadline pushes the connection's write deadline d into the
// future, past the server-wide WriteTimeout, for a handler that legitimately
// responds for longer than it allows. Call it after reading the request body.
// The read deadline needs no help: net/http clears it once the body is
// consumed, so ReadTimeout never cancels a long handler's context. It works
// through middleware that wraps the ResponseWriter as long as the wrapper
// implements Unwrap (otelhttp's httpsnoop wrapper does).
func ExtendWriteDeadline(ctx context.Context, w http.ResponseWriter, d time.Duration) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(d)); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("sse: cannot extend write deadline; the server WriteTimeout may cut this response")
	}
}

// Writer writes the event protocol and remembers whether the response has
// started, so a handler whose work fails before anything was sent can still
// answer with a proper error status instead of an empty 200.
type Writer struct {
	w       http.ResponseWriter
	started bool
}

// NewWriter wraps w. The 200 status and stream headers go out with the first
// event, not before.
func NewWriter(w http.ResponseWriter) *Writer { return &Writer{w: w} }

// Started reports whether any event (and so the 200 status) has been sent.
func (s *Writer) Started() bool { return s.started }

// Text sends one text delta.
func (s *Writer) Text(text string) { s.send(map[string]string{"type": "text", "text": text}) }

// Done sends the terminal success event.
func (s *Writer) Done() { s.send(map[string]string{"type": "done"}) }

// Error sends the terminal failure event. msg is shown to the user, so it
// must not carry internal detail — log the cause instead.
func (s *Writer) Error(msg string) { s.send(map[string]string{"type": "error", "message": msg}) }

func (s *Writer) send(event map[string]string) {
	if !s.started {
		h := s.w.Header()
		h.Set("Content-Type", "text/event-stream")
		h.Set("Cache-Control", "no-cache")
		h.Set("Connection", "keep-alive")
		h.Set("X-Accel-Buffering", "no")
		s.w.WriteHeader(http.StatusOK)
		s.started = true
	}
	payload, _ := json.Marshal(event)
	_, _ = fmt.Fprintf(s.w, "data: %s\n\n", payload)
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}
