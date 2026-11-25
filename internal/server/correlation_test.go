package server

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/rheic/sandboxes-core/ids"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestCorrelationMetadata(t *testing.T) {
	op, req, parent := ids.NewOpID(), ids.NewReqID(), ids.NewReqID()
	for _, tc := range []struct {
		name, value string
		valid       bool
	}{
		{"missing", "", false}, {"valid", op, true}, {"length", "op_short", false},
		{"charset", "op_" + strings.Repeat("!", 26), false}, {"crlf", "op_" + strings.Repeat("a", 24) + "\r\n", false}, {"large", strings.Repeat("x", 4096), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("rheic-op-id", tc.value, "rheic-req-id", req, "rheic-parent-req-id", parent))
			ctx = correlationContext(ctx)
			gotOp, gotReq := ids.FromContext(ctx)
			if ids.Validate(gotOp) != nil || gotReq != req || ParentRequestID(ctx) != parent {
				t.Fatal("invalid correlation context")
			}
			if (gotOp == tc.value) != tc.valid {
				t.Fatal("unexpected regeneration")
			}
		})
	}
}

func TestCorrelationRejectsWithoutLoggingValues(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(logger) })
	secret := "synthetic-secret-value\r\n"
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("rheic-op-id", secret))
	_ = correlationContext(ctx)
	if strings.Contains(buf.String(), secret) || strings.Count(buf.String(), `"event":"rheic.obs.id_rejected"`) != 3 {
		t.Fatalf("unexpected rejection logs: %s", buf.String())
	}
}

type testCorrelationStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *testCorrelationStream) Context() context.Context { return s.ctx }
func TestStreamCorrelationContinuity(t *testing.T) {
	op, req := ids.NewOpID(), ids.NewReqID()
	stream := &testCorrelationStream{ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs("rheic-op-id", op, "rheic-req-id", req))}
	err := StreamCorrelationInterceptor(nil, stream, nil, func(_ any, wrapped grpc.ServerStream) error {
		a, b := ids.FromContext(wrapped.Context())
		c, d := ids.FromContext(wrapped.Context())
		if a != op || b != req || a != c || b != d {
			t.Fatal("stream IDs changed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
