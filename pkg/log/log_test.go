package log_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"

	vglog "github.com/vulngraph/vulngraph/pkg/log"
)

func TestFromContext_AttachesRunAndRequestID(t *testing.T) {
	var buf bytes.Buffer
	zlog.Logger = zerolog.New(&buf)

	ctx := context.Background()
	ctx = vglog.WithRun(ctx, "run-42")
	ctx = vglog.WithRequestID(ctx, "req-7")
	l := vglog.FromContext(ctx)
	l.Info().Msg("hello")

	out := buf.String()
	if !strings.Contains(out, `"run_id":"run-42"`) {
		t.Errorf("missing run_id in log: %s", out)
	}
	if !strings.Contains(out, `"request_id":"req-7"`) {
		t.Errorf("missing request_id in log: %s", out)
	}
}

func TestFromContext_NoCorrelationIDs(t *testing.T) {
	var buf bytes.Buffer
	zlog.Logger = zerolog.New(&buf)

	l := vglog.FromContext(context.Background())
	l.Info().Msg("plain")

	out := buf.String()
	if strings.Contains(out, "run_id") {
		t.Errorf("unexpected run_id in plain log: %s", out)
	}
}

func TestWithRequestID_EmptyDoesNotMutateCtx(t *testing.T) {
	parent := context.Background()
	out := vglog.WithRequestID(parent, "")
	if vglog.RequestIDFromContext(out) != "" {
		t.Error("empty request ID should not be set")
	}
}

func TestRequestIDFromContext(t *testing.T) {
	ctx := vglog.WithRequestID(context.Background(), "req-7")
	if got := vglog.RequestIDFromContext(ctx); got != "req-7" {
		t.Errorf("RequestIDFromContext = %q, want req-7", got)
	}
}
