// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// testDB is the shared database connection for integration tests.
// Initialized in TestMain and available to all test functions.
var testDB *postgres.DB

const defaultTestDSN = "postgres://usulnet_test:test_password_e2e@localhost:15432/usulnet_test?sslmode=disable"

func TestMain(m *testing.M) {
	dsn := os.Getenv("USULNET_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultTestDSN
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := postgres.New(ctx, dsn, postgres.Options{
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: 5 * time.Minute,
	})
	if err != nil {
		// No database available — skip integration tests silently.
		os.Exit(0)
	}

	// Run migrations to ensure schema is up to date.
	if err := db.Migrate(ctx); err != nil {
		db.Close()
		// Migration failure is fatal — schema is broken.
		panic("migration failed: " + err.Error())
	}

	testDB = db
	code := m.Run()
	db.Close()
	os.Exit(code)
}

// truncateTables removes all rows from the given tables.
// Used in t.Cleanup to isolate tests.
func truncateTables(t *testing.T, tables ...string) {
	t.Helper()
	ctx := context.Background()
	for _, table := range tables {
		// TRUNCATE CASCADE handles FK constraints.
		if _, err := testDB.Exec(ctx, "TRUNCATE TABLE "+table+" CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
}
