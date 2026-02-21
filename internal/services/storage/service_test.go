// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// Mock dependencies
// ---------------------------------------------------------------------------

type mockConnRepo struct {
	conns     map[uuid.UUID]*models.StorageConnection
	createErr error
	statuses  map[uuid.UUID]models.StorageConnectionStatus
}

func newMockConnRepo() *mockConnRepo {
	return &mockConnRepo{
		conns:    make(map[uuid.UUID]*models.StorageConnection),
		statuses: make(map[uuid.UUID]models.StorageConnectionStatus),
	}
}

func (r *mockConnRepo) Create(_ context.Context, conn *models.StorageConnection) error {
	if r.createErr != nil {
		return r.createErr
	}
	if conn.ID == uuid.Nil {
		conn.ID = uuid.New()
	}
	r.conns[conn.ID] = conn
	return nil
}

func (r *mockConnRepo) GetByID(_ context.Context, id uuid.UUID) (*models.StorageConnection, error) {
	if c, ok := r.conns[id]; ok {
		return c, nil
	}
	return nil, errors.New("connection not found")
}

func (r *mockConnRepo) List(_ context.Context, _ uuid.UUID) ([]*models.StorageConnection, error) {
	var result []*models.StorageConnection
	for _, c := range r.conns {
		result = append(result, c)
	}
	return result, nil
}

func (r *mockConnRepo) Update(_ context.Context, conn *models.StorageConnection) error {
	r.conns[conn.ID] = conn
	return nil
}

func (r *mockConnRepo) Delete(_ context.Context, id uuid.UUID) error {
	if _, ok := r.conns[id]; !ok {
		return errors.New("connection not found")
	}
	delete(r.conns, id)
	return nil
}

func (r *mockConnRepo) UpdateStatus(_ context.Context, id uuid.UUID, status models.StorageConnectionStatus, _ string) error {
	r.statuses[id] = status
	return nil
}

func (r *mockConnRepo) GetDefault(_ context.Context, _ uuid.UUID) (*models.StorageConnection, error) {
	for _, c := range r.conns {
		if c.IsDefault {
			return c, nil
		}
	}
	return nil, errors.New("no default connection")
}

type mockBucketRepo struct {
	buckets map[uuid.UUID][]*models.StorageBucket
}

func newMockBucketRepo() *mockBucketRepo {
	return &mockBucketRepo{buckets: make(map[uuid.UUID][]*models.StorageBucket)}
}

func (r *mockBucketRepo) Upsert(_ context.Context, b *models.StorageBucket) error {
	if b.ID == uuid.Nil {
		b.ID = uuid.New()
	}
	r.buckets[b.ConnectionID] = append(r.buckets[b.ConnectionID], b)
	return nil
}

func (r *mockBucketRepo) ListByConnection(_ context.Context, connID uuid.UUID) ([]*models.StorageBucket, error) {
	return r.buckets[connID], nil
}

func (r *mockBucketRepo) GetByName(_ context.Context, connID uuid.UUID, name string) (*models.StorageBucket, error) {
	for _, b := range r.buckets[connID] {
		if b.Name == name {
			return b, nil
		}
	}
	return nil, errors.New("bucket not found")
}

func (r *mockBucketRepo) Delete(_ context.Context, connID uuid.UUID, name string) error {
	buckets := r.buckets[connID]
	for i, b := range buckets {
		if b.Name == name {
			r.buckets[connID] = append(buckets[:i], buckets[i+1:]...)
			return nil
		}
	}
	return errors.New("bucket not found")
}

func (r *mockBucketRepo) DeleteByConnection(_ context.Context, connID uuid.UUID) error {
	delete(r.buckets, connID)
	return nil
}

func (r *mockBucketRepo) GetStats(_ context.Context, connID uuid.UUID) (*models.StorageStats, error) {
	buckets := r.buckets[connID]
	return &models.StorageStats{
		TotalBuckets: int64(len(buckets)),
	}, nil
}

type mockAuditRepo struct {
	entries []*models.StorageAuditLog
}

func (r *mockAuditRepo) Create(_ context.Context, e *models.StorageAuditLog) error {
	r.entries = append(r.entries, e)
	return nil
}

func (r *mockAuditRepo) List(_ context.Context, _ uuid.UUID, limit, offset int) ([]*models.StorageAuditLog, int64, error) {
	total := int64(len(r.entries))
	if offset >= len(r.entries) {
		return nil, total, nil
	}
	end := offset + limit
	if end > len(r.entries) {
		end = len(r.entries)
	}
	return r.entries[offset:end], total, nil
}

type mockEncryptor struct{}

func (e *mockEncryptor) EncryptString(plaintext string) (string, error) {
	return "enc:" + plaintext, nil
}
func (e *mockEncryptor) DecryptString(ciphertext string) (string, error) {
	if len(ciphertext) > 4 && ciphertext[:4] == "enc:" {
		return ciphertext[4:], nil
	}
	return ciphertext, nil
}

type mockS3Client struct {
	healthy       bool
	buckets       []BucketInfo
	createErr     error
	deleteErr     error
	listObjResult *ListObjectsResult
}

func (c *mockS3Client) Healthy(_ context.Context) bool { return c.healthy }
func (c *mockS3Client) ListBuckets(_ context.Context) ([]BucketInfo, error) {
	return c.buckets, nil
}
func (c *mockS3Client) CreateBucket(_ context.Context, name, _ string) error {
	if c.createErr != nil {
		return c.createErr
	}
	c.buckets = append(c.buckets, BucketInfo{Name: name, CreatedAt: time.Now()})
	return nil
}
func (c *mockS3Client) DeleteBucket(_ context.Context, _ string) error  { return c.deleteErr }
func (c *mockS3Client) BucketExists(_ context.Context, _ string) (bool, error) { return true, nil }
func (c *mockS3Client) GetBucketVersioning(_ context.Context, _ string) (bool, error) {
	return false, nil
}
func (c *mockS3Client) SetBucketVersioning(_ context.Context, _ string, _ bool) error { return nil }
func (c *mockS3Client) ListObjects(_ context.Context, _, _, _ string, _ int) (*ListObjectsResult, error) {
	if c.listObjResult != nil {
		return c.listObjResult, nil
	}
	return &ListObjectsResult{}, nil
}
func (c *mockS3Client) GetObject(_ context.Context, _, _ string) (io.ReadCloser, *ObjectMeta, error) {
	return io.NopCloser(strings.NewReader("test-data")), &ObjectMeta{Key: "test.txt", ContentLength: 9}, nil
}
func (c *mockS3Client) PutObject(_ context.Context, _, _ string, _ io.Reader, _ int64, _ string) error {
	return nil
}
func (c *mockS3Client) DeleteObject(_ context.Context, _, _ string) error        { return nil }
func (c *mockS3Client) DeleteObjects(_ context.Context, _ string, _ []string) error { return nil }
func (c *mockS3Client) CopyObject(_ context.Context, _, _, _, _ string) error { return nil }
func (c *mockS3Client) PresignGetObject(_ context.Context, _, _ string, _ time.Duration) (string, error) {
	return "https://presigned-get", nil
}
func (c *mockS3Client) PresignPutObject(_ context.Context, _, _ string, _ time.Duration) (string, error) {
	return "https://presigned-put", nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *mockConnRepo, *mockBucketRepo, *mockAuditRepo) {
	t.Helper()
	connRepo := newMockConnRepo()
	bucketRepo := newMockBucketRepo()
	auditRepo := &mockAuditRepo{}
	enc := &mockEncryptor{}
	cfg := Config{DefaultHostID: uuid.New()}
	log := logger.Nop()

	svc := NewService(connRepo, bucketRepo, auditRepo, enc, cfg, log)
	return svc, connRepo, bucketRepo, auditRepo
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestGetConnection(t *testing.T) {
	svc, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.StorageConnection{
		ID:   id,
		Name: "minio-1",
	}

	conn, err := svc.GetConnection(ctx, id)
	if err != nil {
		t.Fatalf("GetConnection failed: %v", err)
	}
	if conn.Name != "minio-1" {
		t.Errorf("expected name minio-1, got %s", conn.Name)
	}
}

func TestGetConnection_NotFound(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.GetConnection(ctx, uuid.New())
	if err == nil {
		t.Error("expected error for non-existent connection")
	}
}

func TestListConnections(t *testing.T) {
	svc, connRepo, _, _ := newTestService(t)
	ctx := context.Background()

	connRepo.conns[uuid.New()] = &models.StorageConnection{ID: uuid.New(), Name: "c1", HostID: svc.config.DefaultHostID}
	connRepo.conns[uuid.New()] = &models.StorageConnection{ID: uuid.New(), Name: "c2", HostID: svc.config.DefaultHostID}

	conns, err := svc.ListConnections(ctx)
	if err != nil {
		t.Fatalf("ListConnections failed: %v", err)
	}
	if len(conns) != 2 {
		t.Errorf("expected 2 connections, got %d", len(conns))
	}
}

func TestDeleteConnection(t *testing.T) {
	svc, connRepo, _, auditRepo := newTestService(t)
	ctx := context.Background()

	id := uuid.New()
	connRepo.conns[id] = &models.StorageConnection{
		ID:        id,
		Name:      "doomed",
		AccessKey: "enc:access",
		SecretKey: "enc:secret",
	}

	err := svc.DeleteConnection(ctx, id, "admin")
	if err != nil {
		t.Fatalf("DeleteConnection failed: %v", err)
	}
	if len(connRepo.conns) != 0 {
		t.Error("expected connection to be deleted")
	}
	if len(auditRepo.entries) == 0 {
		t.Error("expected audit log entry")
	}
}

func TestDeleteConnection_NotFound(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	ctx := context.Background()

	err := svc.DeleteConnection(ctx, uuid.New(), "admin")
	if err == nil {
		t.Error("expected error for non-existent connection")
	}
}

func TestListAuditLogs(t *testing.T) {
	svc, _, _, auditRepo := newTestService(t)
	ctx := context.Background()

	connID := uuid.New()
	auditRepo.entries = []*models.StorageAuditLog{
		{ConnectionID: connID, Action: "create"},
		{ConnectionID: connID, Action: "delete"},
	}

	entries, total, err := svc.ListAuditLogs(ctx, connID, 10, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs failed: %v", err)
	}
	if total != 2 {
		t.Errorf("expected total 2, got %d", total)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

func TestSetLimitProvider(t *testing.T) {
	svc, _, _, _ := newTestService(t)
	// Should not panic
	svc.SetLimitProvider(nil)
}

func TestGetBucketStats(t *testing.T) {
	svc, connRepo, bucketRepo, _ := newTestService(t)
	ctx := context.Background()

	connID := uuid.New()
	connRepo.conns[connID] = &models.StorageConnection{
		ID:        connID,
		Name:      "test",
		AccessKey: "enc:ak",
		SecretKey: "enc:sk",
	}

	bucketRepo.buckets[connID] = []*models.StorageBucket{
		{ConnectionID: connID, Name: "bucket-1"},
		{ConnectionID: connID, Name: "bucket-2"},
	}

	stats, err := svc.GetBucketStats(ctx, connID)
	if err != nil {
		t.Fatalf("GetBucketStats failed: %v", err)
	}
	if stats.TotalBuckets != 2 {
		t.Errorf("expected 2 buckets, got %d", stats.TotalBuckets)
	}
}
