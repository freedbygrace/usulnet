# Load & Performance Tests

## Go Benchmarks

Run Go benchmark tests:

```bash
# Run all benchmarks
go test -bench=. -benchmem ./tests/benchmarks/...

# Run specific benchmark
go test -bench=BenchmarkHealthEndpoint -benchmem ./tests/benchmarks/...

# Run with CPU profiling
go test -bench=. -cpuprofile=cpu.prof -benchmem ./tests/benchmarks/...

# Run with memory profiling
go test -bench=. -memprofile=mem.prof -benchmem ./tests/benchmarks/...
```

## k6 Load Tests

### Prerequisites

Install k6: https://k6.io/docs/getting-started/installation/

### Running

```bash
# Default configuration (ramps to 50 VUs)
k6 run tests/load/k6_api_test.js

# Custom configuration
k6 run --vus 100 --duration 120s tests/load/k6_api_test.js

# Against a specific URL
API_URL=http://staging.example.com k6 run tests/load/k6_api_test.js
```

### SLA Targets

| Metric | Target | Description |
|--------|--------|-------------|
| Health endpoint p95 | < 100ms | Health checks must be fast for K8s probes |
| API request p95 | < 500ms | General API response time |
| Error rate | < 5% | Maximum acceptable error rate |
| Auth latency p95 | < 200ms | Authentication request response time |
