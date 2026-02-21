// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package nats

import (
	"context"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

// ---------------------------------------------------------------------------
// DefaultConfig tests
// ---------------------------------------------------------------------------

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.URL != "nats://localhost:4222" {
		t.Errorf("URL = %q, want %q", cfg.URL, "nats://localhost:4222")
	}
	if cfg.Name != "usulnet-client" {
		t.Errorf("Name = %q, want %q", cfg.Name, "usulnet-client")
	}
	if cfg.MaxReconnects != -1 {
		t.Errorf("MaxReconnects = %d, want -1 (infinite)", cfg.MaxReconnects)
	}
	if cfg.ReconnectWait != 2*time.Second {
		t.Errorf("ReconnectWait = %v, want 2s", cfg.ReconnectWait)
	}
	if cfg.Timeout != 5*time.Second {
		t.Errorf("Timeout = %v, want 5s", cfg.Timeout)
	}
	if cfg.PingInterval != 2*time.Minute {
		t.Errorf("PingInterval = %v, want 2m", cfg.PingInterval)
	}
	if cfg.MaxPingsOut != 3 {
		t.Errorf("MaxPingsOut = %d, want 3", cfg.MaxPingsOut)
	}
	if cfg.ReconnectBufSize != 8*1024*1024 {
		t.Errorf("ReconnectBufSize = %d, want 8MB", cfg.ReconnectBufSize)
	}
	if !cfg.JetStreamEnabled {
		t.Error("JetStreamEnabled should default to true")
	}
}

// ---------------------------------------------------------------------------
// NewClient tests
// ---------------------------------------------------------------------------

func TestNewClient(t *testing.T) {
	client, err := NewClient(DefaultConfig(), nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client == nil {
		t.Fatal("expected non-nil client")
	}
}

func TestNewClient_CustomConfig(t *testing.T) {
	cfg := Config{
		URL:  "nats://custom:4222",
		Name: "test-client",
	}
	client, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if client.config.URL != "nats://custom:4222" {
		t.Errorf("config.URL = %q, want %q", client.config.URL, "nats://custom:4222")
	}
	if client.config.Name != "test-client" {
		t.Errorf("config.Name = %q, want %q", client.config.Name, "test-client")
	}
}

// ---------------------------------------------------------------------------
// Disconnected state tests (no NATS server needed)
// ---------------------------------------------------------------------------

func TestIsConnected_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	if client.IsConnected() {
		t.Error("should not be connected without calling Connect()")
	}
}

func TestIsTLS_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	if client.IsTLS() {
		t.Error("should not report TLS when not connected")
	}
}

func TestHealth_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	err := client.Health(context.Background())
	if err == nil {
		t.Fatal("expected error when not connected")
	}
}

func TestStats_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	stats := client.Stats()
	if stats.InMsgs != 0 || stats.OutMsgs != 0 {
		t.Error("stats should be zero when not connected")
	}
}

func TestServerInfo_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	info := client.ServerInfo()
	if info.ServerID != "" || info.URL != "" {
		t.Error("server info should be empty when not connected")
	}
}

func TestConn_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	if client.Conn() != nil {
		t.Error("Conn() should be nil when not connected")
	}
}

// ---------------------------------------------------------------------------
// Operation errors when not connected
// ---------------------------------------------------------------------------

func TestPublish_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	err := client.Publish("test.subject", []byte("data"))
	if err == nil {
		t.Fatal("expected error when publishing without connection")
	}
}

func TestRequest_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	_, err := client.Request("test.subject", []byte("data"), time.Second)
	if err == nil {
		t.Fatal("expected error when requesting without connection")
	}
}

func TestSubscribe_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	_, err := client.Subscribe("test.subject", nil)
	if err == nil {
		t.Fatal("expected error when subscribing without connection")
	}
}

func TestQueueSubscribe_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	_, err := client.QueueSubscribe("test.subject", "queue", nil)
	if err == nil {
		t.Fatal("expected error when queue subscribing without connection")
	}
}

func TestFlush_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	err := client.Flush()
	if err == nil {
		t.Fatal("expected error when flushing without connection")
	}
}

func TestFlushTimeout_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	err := client.FlushTimeout(time.Second)
	if err == nil {
		t.Fatal("expected error when flush-timeout without connection")
	}
}

// ---------------------------------------------------------------------------
// Close tests
// ---------------------------------------------------------------------------

func TestClose_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	// Should not panic
	client.Close()
}

func TestClose_DoubleClose(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	client.Close()
	client.Close() // should not panic
}

// ---------------------------------------------------------------------------
// Callback registration tests
// ---------------------------------------------------------------------------

func TestCallbacks(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)

	connectCalled := false
	disconnectCalled := false
	reconnectCalled := false

	client.OnConnect(func() { connectCalled = true })
	client.OnDisconnect(func(err error) { disconnectCalled = true })
	client.OnReconnect(func() { reconnectCalled = true })

	// Manually trigger callbacks to verify they were registered
	if client.onConnect == nil {
		t.Error("onConnect callback not registered")
	}
	if client.onDisconnect == nil {
		t.Error("onDisconnect callback not registered")
	}
	if client.onReconnect == nil {
		t.Error("onReconnect callback not registered")
	}

	client.onConnect()
	client.onDisconnect(nil)
	client.onReconnect()

	if !connectCalled {
		t.Error("connect callback not called")
	}
	if !disconnectCalled {
		t.Error("disconnect callback not called")
	}
	if !reconnectCalled {
		t.Error("reconnect callback not called")
	}
}

// ---------------------------------------------------------------------------
// ConnectionStats struct tests
// ---------------------------------------------------------------------------

func TestConnectionStats_Zero(t *testing.T) {
	stats := ConnectionStats{}
	if stats.InMsgs != 0 || stats.OutMsgs != 0 || stats.InBytes != 0 || stats.OutBytes != 0 || stats.Reconnects != 0 {
		t.Error("zero-value stats should all be 0")
	}
}

// ---------------------------------------------------------------------------
// ServerInfo struct tests
// ---------------------------------------------------------------------------

func TestServerInfo_Zero(t *testing.T) {
	info := ServerInfo{}
	if info.ServerID != "" || info.ServerName != "" || info.ClusterName != "" || info.URL != "" {
		t.Error("zero-value ServerInfo should have empty strings")
	}
}

// ---------------------------------------------------------------------------
// Connect error tests (no NATS server running)
// ---------------------------------------------------------------------------

func TestConnect_NoServer(t *testing.T) {
	cfg := Config{
		URL:           "nats://127.0.0.1:54321", // non-existent port
		Name:          "test-fail",
		MaxReconnects: 0,
		Timeout:       100 * time.Millisecond,
	}

	client, err := NewClient(cfg, nil)
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	err = client.Connect(context.Background())
	if err == nil {
		t.Fatal("expected connection error to non-existent server")
	}
}

func TestConnect_AlreadyConnected(t *testing.T) {
	// Cannot test true already-connected without a real server,
	// but we can test the nil conn path
	client, _ := NewClient(DefaultConfig(), nil)
	// conn is nil, so it won't short-circuit; it will try to connect and fail
	// This is really just testing the code path
	if client.IsConnected() {
		t.Error("should not be connected")
	}
}

// ---------------------------------------------------------------------------
// Publisher tests (disconnected state)
// ---------------------------------------------------------------------------

func TestNewPublisher(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)
	if pub == nil {
		t.Fatal("expected non-nil publisher")
	}
}

func TestNewPublisher_NilClient(t *testing.T) {
	pub := NewPublisher(nil)
	if pub == nil {
		t.Fatal("expected non-nil publisher even with nil client")
	}
}

func TestPublisher_Publish_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	err := pub.Publish("test.subject", []byte("data"))
	if err == nil {
		t.Fatal("expected error when publishing without connection")
	}
}

func TestPublisher_PublishJSON_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	err := pub.PublishJSON("test.subject", map[string]string{"key": "value"})
	if err == nil {
		t.Fatal("expected error when publishing JSON without connection")
	}
}

func TestPublisher_PublishMsg_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	err := pub.PublishMsg(nil)
	if err == nil {
		t.Fatal("expected error when publishing msg without connection")
	}
}

func TestPublisher_Request_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	_, err := pub.Request("test.subject", []byte("data"), time.Second)
	if err == nil {
		t.Fatal("expected error when requesting without connection")
	}
}

func TestPublisher_RequestJSON_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	var response map[string]string
	err := pub.RequestJSON("test.subject", "request", &response, time.Second)
	if err == nil {
		t.Fatal("expected error when requesting JSON without connection")
	}
}

func TestPublisher_RequestWithContext_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	_, err := pub.RequestWithContext(context.Background(), "test.subject", []byte("data"))
	if err == nil {
		t.Fatal("expected error when requesting with context without connection")
	}
}

func TestPublisher_RequestJSONWithContext_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	var response map[string]string
	err := pub.RequestJSONWithContext(context.Background(), "test.subject", "request", &response)
	if err == nil {
		t.Fatal("expected error when requesting JSON with context without connection")
	}
}

func TestPublisher_Flush_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	err := pub.Flush()
	if err == nil {
		t.Fatal("expected error when flushing without connection")
	}
}

func TestPublisher_FlushTimeout_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)

	err := pub.FlushTimeout(time.Second)
	if err == nil {
		t.Fatal("expected error when flush-timeout without connection")
	}
}

// ---------------------------------------------------------------------------
// TypedPublisher tests
// ---------------------------------------------------------------------------

func TestNewTypedPublisher(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)
	tp := NewTypedPublisher[map[string]string](pub, "test.typed")
	if tp == nil {
		t.Fatal("expected non-nil typed publisher")
	}
}

func TestTypedPublisher_Publish_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)
	tp := NewTypedPublisher[map[string]string](pub, "test.typed")

	err := tp.Publish(map[string]string{"key": "value"})
	if err == nil {
		t.Fatal("expected error when typed publishing without connection")
	}
}

func TestTypedPublisher_Request_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	pub := NewPublisher(client)
	tp := NewTypedPublisher[string](pub, "test.typed")

	_, err := tp.Request("test", time.Second)
	if err == nil {
		t.Fatal("expected error when typed requesting without connection")
	}
}

// ---------------------------------------------------------------------------
// Subscriber tests (disconnected state)
// ---------------------------------------------------------------------------

func TestNewSubscriber(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)
	if sub == nil {
		t.Fatal("expected non-nil subscriber")
	}
}

func TestNewSubscriber_NilClient(t *testing.T) {
	sub := NewSubscriber(nil)
	if sub == nil {
		t.Fatal("expected non-nil subscriber even with nil client")
	}
}

func TestSubscriber_Subscribe_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.Subscribe("test.subject", func(msg *nats.Msg) error { return nil })
	if err == nil {
		t.Fatal("expected error when subscribing without connection")
	}
}

func TestSubscriber_QueueSubscribe_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.QueueSubscribe("test.subject", "queue", func(msg *nats.Msg) error { return nil })
	if err == nil {
		t.Fatal("expected error when queue subscribing without connection")
	}
}

func TestSubscriber_SubscribeRequest_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.SubscribeRequest("test.subject", func(msg *nats.Msg) ([]byte, error) { return nil, nil })
	if err == nil {
		t.Fatal("expected error when subscribe-request without connection")
	}
}

func TestSubscriber_SubscribeSync_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	_, err := sub.SubscribeSync("test.subject")
	if err == nil {
		t.Fatal("expected error when sync subscribing without connection")
	}
}

func TestSubscriber_SubscribeChan_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	ch := make(chan *nats.Msg, 1)
	err := sub.SubscribeChan("test.subject", ch)
	if err == nil {
		t.Fatal("expected error when chan subscribing without connection")
	}
}

func TestSubscriber_ListSubscriptions_Empty(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	subs := sub.ListSubscriptions()
	if len(subs) != 0 {
		t.Errorf("expected 0 subscriptions, got %d", len(subs))
	}
}

func TestSubscriber_Unsubscribe_NotFound(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.Unsubscribe("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent subscription")
	}
}

func TestSubscriber_Drain_NotFound(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.Drain("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent subscription")
	}
}

func TestSubscriber_Stats_NotFound(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	_, err := sub.Stats("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent subscription")
	}
}

func TestSubscriber_SetPendingLimits_NotFound(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.SetPendingLimits("nonexistent", 100, 1024)
	if err == nil {
		t.Fatal("expected error for nonexistent subscription")
	}
}

func TestSubscriber_Close_Empty(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)

	err := sub.Close()
	if err != nil {
		t.Fatalf("Close() on empty subscriber should not error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// TypedSubscriber tests
// ---------------------------------------------------------------------------

func TestNewTypedSubscriber(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)
	ts := NewTypedSubscriber[map[string]string](sub, "test.typed")
	if ts == nil {
		t.Fatal("expected non-nil typed subscriber")
	}
}

func TestTypedSubscriber_Subscribe_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)
	ts := NewTypedSubscriber[map[string]string](sub, "test.typed")

	err := ts.Subscribe(func(msg map[string]string) error { return nil })
	if err == nil {
		t.Fatal("expected error when typed subscribing without connection")
	}
}

func TestTypedSubscriber_SubscribeWithContext_NotConnected(t *testing.T) {
	client, _ := NewClient(DefaultConfig(), nil)
	sub := NewSubscriber(client)
	ts := NewTypedSubscriber[string](sub, "test.typed")

	err := ts.SubscribeWithContext(context.Background(), func(ctx context.Context, msg string) error { return nil })
	if err == nil {
		t.Fatal("expected error when typed subscribing with context without connection")
	}
}

// ---------------------------------------------------------------------------
// SubscriptionStats struct tests
// ---------------------------------------------------------------------------

func TestSubscriptionStats_Zero(t *testing.T) {
	stats := SubscriptionStats{}
	if stats.Subject != "" || stats.Queue != "" || stats.Delivered != 0 || stats.IsValid {
		t.Error("zero-value SubscriptionStats should have empty/zero fields")
	}
}
