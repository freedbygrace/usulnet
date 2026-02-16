// k6 load test for usulnet API
// Run with: k6 run tests/load/k6_api_test.js
// Or with options: k6 run --vus 50 --duration 60s tests/load/k6_api_test.js

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const errorRate = new Rate('errors');
const healthLatency = new Trend('health_latency', true);
const authLatency = new Trend('auth_latency', true);
const apiLatency = new Trend('api_latency', true);

// Test configuration
export const options = {
  stages: [
    { duration: '10s', target: 10 },  // Ramp up to 10 users
    { duration: '30s', target: 50 },  // Ramp up to 50 users
    { duration: '30s', target: 50 },  // Stay at 50 users
    { duration: '10s', target: 0 },   // Ramp down
  ],
  thresholds: {
    'http_req_duration': ['p(95)<500'],     // 95% of requests under 500ms
    'health_latency': ['p(95)<100'],        // Health checks under 100ms
    'errors': ['rate<0.05'],                // Error rate under 5%
    'http_req_failed': ['rate<0.05'],       // HTTP failures under 5%
  },
};

const BASE_URL = __ENV.API_URL || 'http://localhost:8080';

// Scenario: Health check endpoints
export default function () {
  group('Health Endpoints', function () {
    const healthRes = http.get(`${BASE_URL}/health`);
    healthLatency.add(healthRes.timings.duration);

    check(healthRes, {
      'health status is 200': (r) => r.status === 200,
      'health response has status field': (r) => {
        try {
          const body = JSON.parse(r.body);
          return body.status !== undefined;
        } catch (e) {
          return false;
        }
      },
    }) || errorRate.add(1);

    const versionRes = http.get(`${BASE_URL}/api/v1/system/version`);
    check(versionRes, {
      'version status is 200': (r) => r.status === 200,
    }) || errorRate.add(1);
  });

  group('Unauthenticated API Access', function () {
    // These should return 401
    const endpoints = [
      '/api/v1/system/info',
      '/api/v1/containers',
      '/api/v1/images',
      '/api/v1/volumes',
      '/api/v1/networks',
    ];

    endpoints.forEach((endpoint) => {
      const res = http.get(`${BASE_URL}${endpoint}`);
      apiLatency.add(res.timings.duration);

      check(res, {
        [`${endpoint} returns 401`]: (r) => r.status === 401,
      }) || errorRate.add(1);
    });
  });

  group('Authentication Flow', function () {
    // Test login with invalid credentials
    const loginRes = http.post(
      `${BASE_URL}/api/v1/auth/login`,
      JSON.stringify({ username: 'loadtest', password: 'invalid' }),
      { headers: { 'Content-Type': 'application/json' } }
    );
    authLatency.add(loginRes.timings.duration);

    check(loginRes, {
      'invalid login returns 401': (r) => r.status === 401,
    }) || errorRate.add(1);
  });

  sleep(0.1); // Small pause between iterations
}
