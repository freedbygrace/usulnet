// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestMigrationRollbackIntegrity validates that every up migration has a
// corresponding down migration and that the rollback files are structurally
// sound. This is a static analysis test that does not require a database.
//
// Validates:
//   - Every *.up.sql has a matching *.down.sql
//   - Every *.down.sql has a matching *.up.sql (no orphan rollbacks)
//   - Down migrations contain at least one DROP/DELETE/ALTER statement
//   - CREATE TABLE in up → DROP TABLE in down
//   - CREATE INDEX in up → DROP INDEX in down
//   - CREATE FUNCTION in up → DROP FUNCTION in down
//   - CREATE MATERIALIZED VIEW in up → DROP MATERIALIZED VIEW in down
//   - No empty migration files
func TestMigrationRollbackIntegrity(t *testing.T) {
	migrationsDir := filepath.Join("migrations")

	upFiles, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		t.Fatalf("failed to glob up migrations: %v", err)
	}
	sort.Strings(upFiles)

	downFiles, err := filepath.Glob(filepath.Join(migrationsDir, "*.down.sql"))
	if err != nil {
		t.Fatalf("failed to glob down migrations: %v", err)
	}
	sort.Strings(downFiles)

	if len(upFiles) == 0 {
		t.Fatal("no up migration files found")
	}

	t.Logf("Found %d up migrations, %d down migrations", len(upFiles), len(downFiles))

	// Build maps for quick lookup
	upSet := make(map[string]string) // version -> full path
	downSet := make(map[string]string)

	for _, f := range upFiles {
		version := strings.TrimSuffix(filepath.Base(f), ".up.sql")
		upSet[version] = f
	}
	for _, f := range downFiles {
		version := strings.TrimSuffix(filepath.Base(f), ".down.sql")
		downSet[version] = f
	}

	// 1. Every up migration must have a down migration
	for version := range upSet {
		if _, ok := downSet[version]; !ok {
			t.Errorf("migration %s has no down (rollback) file", version)
		}
	}

	// 2. Every down migration must have a corresponding up migration (no orphans)
	for version := range downSet {
		if _, ok := upSet[version]; !ok {
			t.Errorf("orphan rollback: %s.down.sql has no matching up migration", version)
		}
	}

	// 3. Validate each migration pair
	for version, upPath := range upSet {
		downPath, ok := downSet[version]
		if !ok {
			continue // Already reported above
		}

		t.Run(version, func(t *testing.T) {
			validateMigrationPair(t, version, upPath, downPath)
		})
	}
}

// validateMigrationPair checks structural consistency between an up and down migration.
func validateMigrationPair(t *testing.T, version, upPath, downPath string) {
	t.Helper()

	upContent, err := os.ReadFile(upPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filepath.Base(upPath), err)
	}

	downContent, err := os.ReadFile(downPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", filepath.Base(downPath), err)
	}

	upSQL := string(upContent)
	downSQL := string(downContent)

	// Neither file should be empty
	upTrimmed := strings.TrimSpace(stripSQLComments(upSQL))
	downTrimmed := strings.TrimSpace(stripSQLComments(downSQL))

	if upTrimmed == "" {
		t.Errorf("up migration is empty (no SQL statements)")
	}
	if downTrimmed == "" {
		t.Errorf("down migration is empty (no SQL statements)")
	}

	// Down migration should contain at least one destructive statement
	if downTrimmed != "" && !containsRollbackStatement(downSQL) {
		t.Errorf("down migration contains no DROP/DELETE/ALTER statements — may not properly roll back")
	}

	// Check CREATE TABLE → DROP TABLE
	createdTables := extractMatches(upSQL, reCreateTableName)
	for _, table := range createdTables {
		if !containsDropTable(downSQL, table) {
			t.Errorf("up creates table %q but down does not DROP TABLE %s", table, table)
		}
	}

	// Check CREATE INDEX → DROP INDEX
	createdIndexes := extractMatches(upSQL, reCreateIndexName)
	for _, idx := range createdIndexes {
		if !containsDropIndex(downSQL, idx) {
			t.Errorf("up creates index %q but down does not DROP INDEX %s", idx, idx)
		}
	}

	// Check CREATE [OR REPLACE] FUNCTION → DROP FUNCTION
	createdFunctions := extractMatches(upSQL, reCreateFunctionName)
	for _, fn := range createdFunctions {
		if !containsDropFunction(downSQL, fn) {
			t.Errorf("up creates function %q but down does not DROP FUNCTION %s", fn, fn)
		}
	}

	// Check CREATE MATERIALIZED VIEW → DROP MATERIALIZED VIEW
	createdMViews := extractMatches(upSQL, reCreateMViewName)
	for _, mv := range createdMViews {
		if !containsDropMView(downSQL, mv) {
			t.Errorf("up creates materialized view %q but down does not DROP MATERIALIZED VIEW %s", mv, mv)
		}
	}
}

// TestMigrationDependencyOrder checks that migrations are numbered sequentially
// and that there are no gaps or duplicate version numbers.
func TestMigrationDependencyOrder(t *testing.T) {
	migrationsDir := filepath.Join("migrations")

	files, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		t.Fatalf("failed to glob migrations: %v", err)
	}
	sort.Strings(files)

	// Extract version numbers
	reVersion := regexp.MustCompile(`^(\d+)_`)
	var versions []int
	versionMap := make(map[int]string)

	for _, f := range files {
		base := filepath.Base(f)
		m := reVersion.FindStringSubmatch(base)
		if m == nil {
			t.Errorf("migration %q does not follow NNN_name.up.sql naming convention", base)
			continue
		}
		num := 0
		fmt.Sscanf(m[1], "%d", &num)

		if existing, ok := versionMap[num]; ok {
			t.Errorf("duplicate migration version %d: %s and %s", num, existing, base)
		}
		versionMap[num] = base
		versions = append(versions, num)
	}

	sort.Ints(versions)

	// Check for version 1 starting point
	if len(versions) > 0 && versions[0] != 1 {
		t.Errorf("migrations should start at version 1, but first version is %d", versions[0])
	}

	// Check for gaps
	for i := 1; i < len(versions); i++ {
		if versions[i] != versions[i-1]+1 {
			t.Errorf("gap in migration versions: %d to %d (missing %d)",
				versions[i-1], versions[i], versions[i-1]+1)
		}
	}

	t.Logf("Migration versions: %d to %d (%d total, no gaps)", versions[0], versions[len(versions)-1], len(versions))
}

// TestMigrationRollbackFullSequence simulates applying all migrations up and
// then rolling them all back, verifying that the down files exist and would
// result in no leftover tables by static analysis.
//
// For each migration processed in reverse order, it tracks which tables are
// created vs dropped, ensuring all are accounted for after full rollback.
func TestMigrationRollbackFullSequence(t *testing.T) {
	migrationsDir := filepath.Join("migrations")

	upFiles, err := filepath.Glob(filepath.Join(migrationsDir, "*.up.sql"))
	if err != nil {
		t.Fatalf("failed to glob migrations: %v", err)
	}
	sort.Strings(upFiles)

	// Phase 1: "Apply" all up migrations (collect created tables)
	allCreatedTables := make(map[string]string) // table -> migration version
	allDroppedByUp := make(map[string]bool)     // tables dropped by up migrations

	for _, f := range upFiles {
		version := strings.TrimSuffix(filepath.Base(f), ".up.sql")
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("failed to read %s: %v", f, err)
		}
		sql := string(content)

		for _, table := range extractMatches(sql, reCreateTableName) {
			allCreatedTables[table] = version
		}

		// Track tables dropped by up migrations (e.g., table renames)
		for _, table := range extractMatches(sql, reDropTableName) {
			allDroppedByUp[table] = true
			delete(allCreatedTables, table)
		}
	}

	t.Logf("Total tables created by all up migrations: %d", len(allCreatedTables))

	// Phase 2: "Rollback" all down migrations in reverse order
	downFiles, err := filepath.Glob(filepath.Join(migrationsDir, "*.down.sql"))
	if err != nil {
		t.Fatalf("failed to glob down migrations: %v", err)
	}
	sort.Strings(downFiles)

	droppedByDown := make(map[string]bool)
	for i := len(downFiles) - 1; i >= 0; i-- {
		content, err := os.ReadFile(downFiles[i])
		if err != nil {
			t.Fatalf("failed to read %s: %v", downFiles[i], err)
		}
		sql := string(content)

		for _, table := range extractMatches(sql, reDropTableName) {
			droppedByDown[table] = true
		}
	}

	// Phase 3: Verify all created tables would be dropped by rollback
	var orphanTables []string
	for table := range allCreatedTables {
		if !droppedByDown[table] {
			orphanTables = append(orphanTables, table)
		}
	}

	sort.Strings(orphanTables)
	if len(orphanTables) > 0 {
		t.Errorf("tables that would remain after full rollback (orphan tables):\n  %s",
			strings.Join(orphanTables, "\n  "))
	} else {
		t.Logf("All %d tables would be properly dropped by full rollback", len(allCreatedTables))
	}
}

// =========================================================================
// Helper functions
// =========================================================================

var (
	reCreateTableName    = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	reCreateIndexName    = regexp.MustCompile(`(?i)CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	reCreateFunctionName = regexp.MustCompile(`(?i)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(\w+)`)
	reCreateMViewName    = regexp.MustCompile(`(?i)CREATE\s+MATERIALIZED\s+VIEW\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	reDropTableName      = regexp.MustCompile(`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)`)
)

func extractMatches(sql string, re *regexp.Regexp) []string {
	matches := re.FindAllStringSubmatch(sql, -1)
	var result []string
	seen := make(map[string]bool)
	for _, m := range matches {
		name := strings.ToLower(m[1])
		if !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}
	return result
}

func containsDropTable(sql, table string) bool {
	re := regexp.MustCompile(`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?` + regexp.QuoteMeta(table))
	return re.MatchString(sql)
}

func containsDropIndex(sql, index string) bool {
	re := regexp.MustCompile(`(?i)DROP\s+INDEX\s+(?:IF\s+EXISTS\s+)?` + regexp.QuoteMeta(index))
	return re.MatchString(sql)
}

func containsDropFunction(sql, fn string) bool {
	re := regexp.MustCompile(`(?i)DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?` + regexp.QuoteMeta(fn))
	return re.MatchString(sql)
}

func containsDropMView(sql, mv string) bool {
	re := regexp.MustCompile(`(?i)DROP\s+MATERIALIZED\s+VIEW\s+(?:IF\s+EXISTS\s+)?` + regexp.QuoteMeta(mv))
	return re.MatchString(sql)
}

func containsRollbackStatement(sql string) bool {
	rollbackPatterns := []string{
		`(?i)\bDROP\s+`,
		`(?i)\bDELETE\s+`,
		`(?i)\bALTER\s+TABLE\s+`,
		`(?i)\bTRUNCATE\s+`,
	}
	for _, pattern := range rollbackPatterns {
		if matched, _ := regexp.MatchString(pattern, sql); matched {
			return true
		}
	}
	return false
}

// stripSQLComments removes SQL line comments (--) and block comments (/* */).
func stripSQLComments(sql string) string {
	// Remove block comments
	reBlock := regexp.MustCompile(`/\*[\s\S]*?\*/`)
	sql = reBlock.ReplaceAllString(sql, "")

	// Remove line comments
	var lines []string
	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "--") {
			// Remove inline comments
			if idx := strings.Index(line, "--"); idx >= 0 {
				line = line[:idx]
			}
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n")
}
