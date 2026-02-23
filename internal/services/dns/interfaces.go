// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import (
	"context"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
)

// ZoneRepository defines persistence operations for DNS zones.
type ZoneRepository interface {
	Create(ctx context.Context, z *models.DNSZone) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DNSZone, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.DNSZone, error)
	ListAll(ctx context.Context) ([]*models.DNSZone, error)
	Update(ctx context.Context, z *models.DNSZone) error
	Delete(ctx context.Context, id uuid.UUID) error
	IncrementSerial(ctx context.Context, id uuid.UUID) error
}

// RecordRepository defines persistence operations for DNS records.
type RecordRepository interface {
	Create(ctx context.Context, rec *models.DNSRecord) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DNSRecord, error)
	ListByZone(ctx context.Context, zoneID uuid.UUID) ([]*models.DNSRecord, error)
	Update(ctx context.Context, rec *models.DNSRecord) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// TSIGKeyRepository defines persistence operations for TSIG keys.
type TSIGKeyRepository interface {
	Create(ctx context.Context, k *models.DNSTSIGKey) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.DNSTSIGKey, error)
	List(ctx context.Context, hostID uuid.UUID) ([]*models.DNSTSIGKey, error)
	Update(ctx context.Context, k *models.DNSTSIGKey) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// AuditLogRepository defines persistence for DNS audit logs.
type AuditLogRepository interface {
	Create(ctx context.Context, entry *models.DNSAuditLog) error
	List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error)
}

// Encryptor handles encryption/decryption of sensitive data (TSIG secrets).
type Encryptor interface {
	EncryptString(plaintext string) (string, error)
	DecryptString(ciphertext string) (string, error)
}
