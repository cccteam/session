package basesession

import (
	"context"

	"github.com/cccteam/session/sessioninfo"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// impersonationSpanAttributes renders the record's evidence as span attributes, under
// the same keys the log entry carries.
func impersonationSpanAttributes(imp *sessioninfo.Impersonation) []attribute.KeyValue {
	attrs := imp.Attributes()
	kvs := make([]attribute.KeyValue, 0, len(attrs))
	for _, a := range attrs {
		kvs = append(kvs, attribute.String(a.Key, a.Value))
	}

	return kvs
}

// addImpersonationSpanEvent records a lifecycle event of an impersonated session on the
// span in ctx, as "impersonation.<Kind>" carrying the record's evidence plus the
// operation and end reason when set. Without a span in ctx it is a no-op.
func addImpersonationSpanEvent(ctx context.Context, kind sessioninfo.ImpersonationEventKind, imp *sessioninfo.Impersonation, operation string) {
	kvs := impersonationSpanAttributes(imp)
	if operation != "" {
		kvs = append(kvs, attribute.String("impersonation.operation", operation))
	}
	if imp.EndReason != "" {
		kvs = append(kvs, attribute.String("impersonation.end_reason", string(imp.EndReason)))
	}

	trace.SpanFromContext(ctx).AddEvent("impersonation."+string(kind), trace.WithAttributes(kvs...))
}
