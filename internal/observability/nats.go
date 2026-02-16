// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package observability

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// ============================================================================
// NATS Messaging Tracing
// ============================================================================

// NATSSpanOptions configures a span for a NATS publish/subscribe operation.
type NATSSpanOptions struct {
	// Operation is the NATS operation type: "publish", "subscribe", "request".
	Operation string
	// Subject is the NATS subject being published to or subscribed on.
	Subject string
	// AgentID identifies the remote agent involved (if applicable).
	AgentID string
	// PayloadSize is the size of the message payload in bytes.
	PayloadSize int
}

// StartNATSSpan starts a new child span for a NATS messaging operation and
// returns the updated context and span. The caller must call span.End() when
// the operation completes.
//
// Usage:
//
//	ctx, span := observability.StartNATSSpan(ctx, observability.NATSSpanOptions{
//	    Operation: "publish",
//	    Subject:   "agent.cmd.container.list",
//	    AgentID:   agentID,
//	})
//	defer span.End()
func StartNATSSpan(ctx context.Context, opts NATSSpanOptions) (context.Context, trace.Span) {
	spanName := "nats"
	if opts.Operation != "" && opts.Subject != "" {
		spanName = fmt.Sprintf("nats.%s %s", opts.Operation, opts.Subject)
	} else if opts.Operation != "" {
		spanName = fmt.Sprintf("nats.%s", opts.Operation)
	}

	kind := trace.SpanKindProducer
	if opts.Operation == "subscribe" {
		kind = trace.SpanKindConsumer
	}

	attrs := []attribute.KeyValue{
		attribute.String("messaging.system", "nats"),
		attribute.String("messaging.operation", opts.Operation),
	}
	if opts.Subject != "" {
		attrs = append(attrs, attribute.String("messaging.destination.name", opts.Subject))
	}
	if opts.AgentID != "" {
		attrs = append(attrs, attribute.String("messaging.agent.id", opts.AgentID))
	}
	if opts.PayloadSize > 0 {
		attrs = append(attrs, attribute.Int("messaging.message.body.size", opts.PayloadSize))
	}

	return StartSpan(ctx, spanName,
		trace.WithSpanKind(kind),
		trace.WithAttributes(attrs...),
	)
}
