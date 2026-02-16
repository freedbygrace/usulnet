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
// Docker Engine Tracing
// ============================================================================

// DockerSpanOptions configures a span for a Docker Engine operation.
type DockerSpanOptions struct {
	// Operation is the Docker operation name (e.g., "container.list", "image.pull",
	// "container.start", "container.stop", "volume.create").
	Operation string
	// ContainerID is the container ID if the operation targets a specific container.
	ContainerID string
	// ImageRef is the image reference if the operation involves an image (e.g., "nginx:latest").
	ImageRef string
	// HostID is the host where the Docker operation is executed.
	HostID string
}

// StartDockerSpan starts a new child span for a Docker Engine operation and
// returns the updated context and span. The caller must call span.End() when
// the operation completes.
//
// Usage:
//
//	ctx, span := observability.StartDockerSpan(ctx, observability.DockerSpanOptions{
//	    Operation:   "container.list",
//	    HostID:      hostID.String(),
//	})
//	defer span.End()
func StartDockerSpan(ctx context.Context, opts DockerSpanOptions) (context.Context, trace.Span) {
	spanName := "docker"
	if opts.Operation != "" {
		spanName = fmt.Sprintf("docker.%s", opts.Operation)
	}

	attrs := []attribute.KeyValue{
		attribute.String("docker.operation", opts.Operation),
	}
	if opts.ContainerID != "" {
		attrs = append(attrs, attribute.String("docker.container.id", opts.ContainerID))
	}
	if opts.ImageRef != "" {
		attrs = append(attrs, attribute.String("docker.image.ref", opts.ImageRef))
	}
	if opts.HostID != "" {
		attrs = append(attrs, attribute.String("docker.host.id", opts.HostID))
	}

	return StartSpan(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
}

// RecordDockerResult annotates the current span with the outcome of a Docker
// operation (e.g., number of containers returned, image size pulled).
func RecordDockerResult(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	if span.IsRecording() {
		span.SetAttributes(attrs...)
	}
}
