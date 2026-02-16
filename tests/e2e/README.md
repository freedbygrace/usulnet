# End-to-End Tests

## Prerequisites

1. Docker and Docker Compose installed
2. Go 1.25+ installed

## Running E2E Tests

### 1. Start the test environment

```bash
docker compose -f docker-compose.test.yml up -d
```

### 2. Wait for services to be healthy

```bash
docker compose -f docker-compose.test.yml ps
```

### 3. Run the E2E tests

```bash
# Against the test services directly
go test -tags=e2e -v ./tests/e2e/...

# Against a running usulnet instance
USULNET_TEST_API_URL=http://localhost:8080 go test -tags=e2e -v ./tests/e2e/...
```

### 4. Clean up

```bash
docker compose -f docker-compose.test.yml down -v
```

## Test Structure

- `e2e_test.go` - Main test suite with API client and test helpers
- Tests are gated with `//go:build e2e` tag to prevent running in normal `go test`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `USULNET_TEST_DATABASE_URL` | `postgres://usulnet_test:test_password_e2e@localhost:15432/usulnet_test?sslmode=disable` | PostgreSQL connection for test DB |
| `USULNET_TEST_REDIS_URL` | `redis://localhost:16379` | Redis connection for test cache |
| `USULNET_TEST_NATS_URL` | `nats://localhost:14222` | NATS connection for test messaging |
| `USULNET_TEST_API_URL` | *(empty)* | API URL for testing against running server |
