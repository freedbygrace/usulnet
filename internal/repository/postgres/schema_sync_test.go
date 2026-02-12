// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestSchemaSyncMigrationsVsRepositories is a regression test that parses
// migration SQL files and repository Go files to detect column mismatches.
//
// It builds a schema map from CREATE TABLE / ALTER TABLE ADD COLUMN in
// migrations, then checks INSERT INTO column lists in repository code
// against the known schema. Any column referenced in an INSERT but not
// present in the migration schema is reported as a drift.
//
// This test does NOT require a running database — it operates purely on
// source file analysis.
func TestSchemaSyncMigrationsVsRepositories(t *testing.T) {
	migrationsDir := filepath.Join("migrations")
	repoDir := "."

	// 1. Build schema from migrations
	schema, err := parseMigrationSchema(migrationsDir)
	if err != nil {
		t.Fatalf("Failed to parse migration schema: %v", err)
	}

	if len(schema) == 0 {
		t.Fatal("No tables found in migrations — check migrations directory path")
	}

	t.Logf("Parsed %d tables from migrations", len(schema))

	// 2. Extract INSERT column references from repository Go files
	insertRefs, err := parseRepoInserts(repoDir)
	if err != nil {
		t.Fatalf("Failed to parse repository files: %v", err)
	}

	t.Logf("Found %d INSERT references across repository files", len(insertRefs))

	// 3. Compare: every INSERT column should exist in the migration schema
	var drifts []string
	for _, ref := range insertRefs {
		tableCols, ok := schema[ref.table]
		if !ok {
			// Table not found in migrations — might be a different schema
			// or a test-only table. Log but don't fail.
			t.Logf("NOTICE: table %q referenced in %s not found in migrations", ref.table, ref.file)
			continue
		}

		for _, col := range ref.columns {
			if !tableCols[col] {
				drifts = append(drifts, fmt.Sprintf(
					"column %q in INSERT INTO %s (%s) — not in migration schema",
					col, ref.table, ref.file,
				))
			}
		}
	}

	if len(drifts) > 0 {
		sort.Strings(drifts)
		t.Errorf("Found %d schema drift(s):\n  %s", len(drifts), strings.Join(drifts, "\n  "))
	}
}

// TestMigrationSchemaCompleteness verifies that the migration parser finds a
// reasonable number of tables and that key tables have expected columns.
func TestMigrationSchemaCompleteness(t *testing.T) {
	schema, err := parseMigrationSchema(filepath.Join("migrations"))
	if err != nil {
		t.Fatalf("Failed to parse migrations: %v", err)
	}

	// Spot-check: essential tables must exist
	essentialTables := []string{
		"users", "hosts", "containers", "jobs", "backups",
		"stacks", "security_scans", "notification_configs",
	}
	for _, table := range essentialTables {
		if _, ok := schema[table]; !ok {
			t.Errorf("Essential table %q not found in migration schema", table)
		}
	}

	// Spot-check: users table must have certain columns
	if userCols, ok := schema["users"]; ok {
		for _, col := range []string{"id", "username", "password_hash", "role", "is_active"} {
			if !userCols[col] {
				t.Errorf("users table missing expected column %q", col)
			}
		}
	}

	// Spot-check: containers table
	if containerCols, ok := schema["containers"]; ok {
		for _, col := range []string{"id", "host_id", "name", "image", "status"} {
			if !containerCols[col] {
				t.Errorf("containers table missing expected column %q", col)
			}
		}
	}

	// Spot-check: jobs table
	if jobCols, ok := schema["jobs"]; ok {
		for _, col := range []string{"id", "type", "status", "priority"} {
			if !jobCols[col] {
				t.Errorf("jobs table missing expected column %q", col)
			}
		}
	}
}

// =========================================================================
// SQL Migration Parser
// =========================================================================

// parseMigrationSchema reads all *.up.sql files and returns a map of
// table_name → set_of_column_names.
func parseMigrationSchema(dir string) (map[string]map[string]bool, error) {
	schema := make(map[string]map[string]bool)

	files, err := filepath.Glob(filepath.Join(dir, "*.up.sql"))
	if err != nil {
		return nil, fmt.Errorf("glob migrations: %w", err)
	}

	// Sort to process in order
	sort.Strings(files)

	for _, f := range files {
		if err := parseSQLFile(f, schema); err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(f), err)
		}
	}

	return schema, nil
}

// Regex patterns for SQL parsing
var (
	// CREATE TABLE [IF NOT EXISTS] table_name (
	reCreateTable = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(`)
	// ALTER TABLE table_name ADD [COLUMN] [IF NOT EXISTS] column_name
	reAlterAddColumn = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)\s+ADD\s+(?:COLUMN\s+)?(?:IF\s+NOT\s+EXISTS\s+)?(\w+)`)
	// ALTER TABLE table_name RENAME COLUMN old_name TO new_name
	reAlterRenameColumn = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)\s+RENAME\s+COLUMN\s+(\w+)\s+TO\s+(\w+)`)
	// ALTER TABLE table_name DROP COLUMN column_name
	reAlterDropColumn = regexp.MustCompile(`(?i)ALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(\w+)\s+DROP\s+COLUMN\s+(?:IF\s+EXISTS\s+)?(\w+)`)
)

// parseSQLFile reads a single migration SQL file and populates the schema map.
func parseSQLFile(path string, schema map[string]map[string]bool) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	content := string(data)

	// Parse CREATE TABLE blocks
	parseCreateTables(content, schema)

	// Parse ALTER TABLE ADD COLUMN
	for _, m := range reAlterAddColumn.FindAllStringSubmatch(content, -1) {
		table := strings.ToLower(m[1])
		col := strings.ToLower(m[2])
		if schema[table] == nil {
			schema[table] = make(map[string]bool)
		}
		schema[table][col] = true
	}

	// Parse ALTER TABLE RENAME COLUMN
	for _, m := range reAlterRenameColumn.FindAllStringSubmatch(content, -1) {
		table := strings.ToLower(m[1])
		oldCol := strings.ToLower(m[2])
		newCol := strings.ToLower(m[3])
		if schema[table] != nil {
			delete(schema[table], oldCol)
			schema[table][newCol] = true
		}
	}

	// Parse ALTER TABLE DROP COLUMN
	for _, m := range reAlterDropColumn.FindAllStringSubmatch(content, -1) {
		table := strings.ToLower(m[1])
		col := strings.ToLower(m[2])
		if schema[table] != nil {
			delete(schema[table], col)
		}
	}

	return nil
}

// parseCreateTables extracts column names from CREATE TABLE (...) blocks.
func parseCreateTables(sql string, schema map[string]map[string]bool) {
	matches := reCreateTable.FindAllStringSubmatchIndex(sql, -1)

	for _, loc := range matches {
		tableName := strings.ToLower(sql[loc[2]:loc[3]])
		// Find the matching closing paren for the column definition block
		startParen := loc[1] - 1 // position of the opening '('
		endParen := findMatchingParen(sql, startParen)
		if endParen < 0 {
			continue
		}

		columnBlock := sql[startParen+1 : endParen]
		cols := parseColumnBlock(columnBlock)

		if schema[tableName] == nil {
			schema[tableName] = make(map[string]bool)
		}
		for _, col := range cols {
			schema[tableName][col] = true
		}
	}
}

// findMatchingParen finds the closing ')' matching the opening '(' at pos.
func findMatchingParen(s string, pos int) int {
	depth := 0
	for i := pos; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseColumnBlock extracts column names from the CREATE TABLE (...) body.
// It skips constraints (PRIMARY KEY, FOREIGN KEY, UNIQUE, CHECK, CONSTRAINT, INDEX).
func parseColumnBlock(block string) []string {
	var cols []string

	// Split by commas, but respect parentheses (for CHECK constraints, etc.)
	lines := splitRespectingParens(block)

	skipPrefixes := []string{
		"primary key", "foreign key", "unique", "check", "constraint",
		"create index", "create unique", "exclude",
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		lower := strings.ToLower(line)

		// Skip constraint lines
		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(lower, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// First word is the column name (skip if it looks like a SQL keyword)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		colName := strings.ToLower(fields[0])
		// Skip if it's a SQL keyword rather than a column name
		sqlKeywords := map[string]bool{
			"primary": true, "foreign": true, "unique": true,
			"check": true, "constraint": true, "index": true,
			"create": true, "alter": true, "drop": true,
			"if": true, "not": true, "null": true, "--": true,
		}
		if sqlKeywords[colName] || strings.HasPrefix(colName, "--") {
			continue
		}

		// Strip quotes
		colName = strings.Trim(colName, `"'`)
		if colName != "" {
			cols = append(cols, colName)
		}
	}

	return cols
}

// splitRespectingParens splits a string by commas, but ignores commas
// inside parenthesized groups (for things like CHECK constraints).
func splitRespectingParens(s string) []string {
	var result []string
	depth := 0
	start := 0

	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				result = append(result, s[start:i])
				start = i + 1
			}
		}
	}

	// Last segment
	if start < len(s) {
		result = append(result, s[start:])
	}

	return result
}

// =========================================================================
// Repository Go File Parser
// =========================================================================

// insertRef represents a column reference found in an INSERT INTO statement.
type insertRef struct {
	file    string
	table   string
	columns []string
}

// parseRepoInserts scans repository Go files for INSERT INTO statements
// and extracts table + column references.
func parseRepoInserts(dir string) ([]insertRef, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*_repo*.go"))
	if err != nil {
		return nil, err
	}

	// Also include files matching *_repository*.go
	repoFiles, err := filepath.Glob(filepath.Join(dir, "*_repository*.go"))
	if err != nil {
		return nil, err
	}
	files = append(files, repoFiles...)

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, f := range files {
		if !seen[f] {
			seen[f] = true
			unique = append(unique, f)
		}
	}

	// Skip test files
	var srcFiles []string
	for _, f := range unique {
		if !strings.HasSuffix(f, "_test.go") {
			srcFiles = append(srcFiles, f)
		}
	}

	var refs []insertRef
	for _, f := range srcFiles {
		fileRefs, err := parseGoFileForInserts(f)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(f), err)
		}
		refs = append(refs, fileRefs...)
	}

	return refs, nil
}

// Regex to find INSERT INTO table (col1, col2, ...) in Go string literals.
// Handles multi-line backtick strings by working on concatenated content.
var reInsertInto = regexp.MustCompile(`(?i)INSERT\s+INTO\s+(\w+)\s*\(([^)]+)\)`)

// parseGoFileForInserts reads a Go file and extracts INSERT INTO references.
func parseGoFileForInserts(path string) ([]insertRef, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read all lines and join into one big string for multi-line matching
	var sb strings.Builder
	scanner := bufio.NewScanner(f)
	// Increase scanner buffer for large files
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		sb.WriteString(scanner.Text())
		sb.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	content := sb.String()
	baseName := filepath.Base(path)

	var refs []insertRef
	for _, m := range reInsertInto.FindAllStringSubmatch(content, -1) {
		table := strings.ToLower(m[1])
		colStr := m[2]

		// Parse column list
		cols := parseColumnList(colStr)
		if len(cols) > 0 {
			refs = append(refs, insertRef{
				file:    baseName,
				table:   table,
				columns: cols,
			})
		}
	}

	return refs, nil
}

// parseColumnList splits "col1, col2, col3" into individual column names,
// filtering out SQL placeholders ($1, ?, etc.) and expressions.
func parseColumnList(s string) []string {
	parts := strings.Split(s, ",")
	var cols []string

	for _, p := range parts {
		col := strings.TrimSpace(p)
		col = strings.ToLower(col)

		// Remove newlines and extra whitespace
		col = strings.Join(strings.Fields(col), " ")

		// Skip placeholders, expressions, empty
		if col == "" {
			continue
		}
		if strings.HasPrefix(col, "$") || strings.HasPrefix(col, "?") {
			continue
		}
		if strings.Contains(col, "(") || strings.Contains(col, ")") {
			continue
		}

		// Strip any alias (e.g., "col AS alias")
		if idx := strings.Index(col, " "); idx > 0 {
			col = col[:idx]
		}

		// Strip quotes
		col = strings.Trim(col, `"'`)

		if col != "" && !strings.HasPrefix(col, "--") {
			cols = append(cols, col)
		}
	}

	return cols
}
