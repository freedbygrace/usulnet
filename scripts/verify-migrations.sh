#!/usr/bin/env bash
# verify-migrations.sh - CI script to validate migration integrity
#
# Runs the migration rollback validation tests without requiring a database.
# Exit code 0 = all checks pass, non-zero = failures detected.
#
# Usage:
#   ./scripts/verify-migrations.sh
#   # Or with verbose output:
#   VERBOSE=1 ./scripts/verify-migrations.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== Migration Integrity Verification ==="
echo "Project root: ${PROJECT_ROOT}"
echo ""

# Count migrations
UP_COUNT=$(find "${PROJECT_ROOT}/internal/repository/postgres/migrations" -name "*.up.sql" | wc -l)
DOWN_COUNT=$(find "${PROJECT_ROOT}/internal/repository/postgres/migrations" -name "*.down.sql" | wc -l)
echo "Found ${UP_COUNT} up migrations, ${DOWN_COUNT} down migrations"
echo ""

# Check for missing pairs
MISSING=0
for up_file in "${PROJECT_ROOT}"/internal/repository/postgres/migrations/*.up.sql; do
    base=$(basename "$up_file" .up.sql)
    down_file="${PROJECT_ROOT}/internal/repository/postgres/migrations/${base}.down.sql"
    if [ ! -f "$down_file" ]; then
        echo "ERROR: Missing rollback: ${base}.down.sql"
        MISSING=$((MISSING + 1))
    fi
done

for down_file in "${PROJECT_ROOT}"/internal/repository/postgres/migrations/*.down.sql; do
    base=$(basename "$down_file" .down.sql)
    up_file="${PROJECT_ROOT}/internal/repository/postgres/migrations/${base}.up.sql"
    if [ ! -f "$up_file" ]; then
        echo "ERROR: Orphan rollback: ${base}.down.sql (no matching up migration)"
        MISSING=$((MISSING + 1))
    fi
done

if [ "$MISSING" -gt 0 ]; then
    echo ""
    echo "FAIL: ${MISSING} migration pair(s) incomplete"
    exit 1
fi

echo "All migration pairs present."
echo ""

# Check for empty down files
EMPTY=0
for down_file in "${PROJECT_ROOT}"/internal/repository/postgres/migrations/*.down.sql; do
    content=$(grep -v '^--' "$down_file" | grep -v '^\s*$' || true)
    if [ -z "$content" ]; then
        echo "WARNING: Empty rollback file: $(basename "$down_file")"
        EMPTY=$((EMPTY + 1))
    fi
done

if [ "$EMPTY" -gt 0 ]; then
    echo "WARNING: ${EMPTY} down migration(s) appear empty"
fi

# Run Go tests if Go is available
if command -v go &> /dev/null; then
    echo ""
    echo "Running migration integrity tests..."
    VERBOSE_FLAG=""
    if [ "${VERBOSE:-0}" = "1" ]; then
        VERBOSE_FLAG="-v"
    fi

    cd "${PROJECT_ROOT}"
    go test ./internal/repository/postgres/ \
        -run "TestMigrationRollback|TestMigrationDependencyOrder" \
        ${VERBOSE_FLAG} \
        -count=1 \
        -timeout 60s
    echo ""
    echo "All migration tests passed."
else
    echo ""
    echo "Go not available — skipping Go test execution (file pair checks passed)"
fi

echo ""
echo "=== Migration verification complete ==="
