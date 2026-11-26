// Correlation IDs link observations only; they are never identity or authorization material.
package server

import (
	"context"
	"log/slog"
	"strings"

	"github.com/gyrel/sandboxes-core/ids"
	"github.com/gyrel/slogx/events"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type parentRequestKey struct{}

// ParentRequestID returns the validated incoming parent request correlation ID.
func ParentRequestID(ctx context.Context) string {
	v, _ := ctx.Value(parentRequestKey{}).(string)
	return v
}

func correlationContext(ctx context.Context) context.Context {
	md, _ := metadata.FromIncomingContext(ctx)
	read := func(key, prefix string, field events.ObsIDRejectedField, generate func() string) string {
		values := md.Get(key)
		value := ""
		if len(values) == 1 {
			value = values[0]
		}
		if len(values) == 1 && strings.HasPrefix(value, prefix) && ids.Validate(value) == nil {
			return value
		}
		rule := events.ObsIDRejectedRuleCanonicalLength
		if len(values) == 1 && len(value) == len(prefix)+26 {
			rule = events.ObsIDRejectedRuleCharset
			if !strings.HasPrefix(value, prefix) {
				rule = events.ObsIDRejectedRulePrefix
			}
		}
		event, err := events.ObsIDRejected(events.OutcomeDenied, events.ObsIDRejectedParams{Component: events.ComponentDaemon, Field: field, Rule: rule, Regenerated: true})
		if err == nil {
			event.Emit(ctx, slog.Default(), events.Standard{})
		}
		return generate()
	}
	op := read("gyrel-op-id", "op_", events.ObsIDRejectedFieldOpID, ids.NewOpID)
	req := read("gyrel-req-id", "req_", events.ObsIDRejectedFieldReqID, ids.NewReqID)
	parent := read("gyrel-parent-req-id", "req_", events.ObsIDRejectedFieldParentReqID, ids.NewReqID)
	ctx = ids.WithOpID(ctx, op)
	ctx = ids.WithReqID(ctx, req)
	return context.WithValue(ctx, parentRequestKey{}, parent)
}

// UnaryCorrelationInterceptor validates untrusted correlation metadata.
func UnaryCorrelationInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	return handler(correlationContext(ctx), req)
}

type correlationStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *correlationStream) Context() context.Context { return s.ctx }

// StreamCorrelationInterceptor keeps correlation IDs stable for a stream's lifetime.
func StreamCorrelationInterceptor(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	return handler(srv, &correlationStream{ServerStream: stream, ctx: correlationContext(stream.Context())})
}
