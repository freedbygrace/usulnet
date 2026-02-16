// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package benchmarks

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
)

const benchJWTSecret = "benchmark-secret-key-for-testing-purposes-only-minimum-32"

func setupBenchRouter() http.Handler {
	systemHandler := handlers.NewSystemHandler("bench-version", "bench-commit", "2026-01-01", nil)
	systemHandler.RegisterHealthChecker("mock-db", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "up", Latency: 1}
	})
	systemHandler.RegisterHealthChecker("mock-redis", func(ctx context.Context) *handlers.HealthStatus {
		return &handlers.HealthStatus{Status: "up", Latency: 1}
	})

	h := &api.Handlers{
		System: systemHandler,
	}

	config := api.RouterConfig{
		JWTSecret:          benchJWTSecret,
		CORSConfig:         middleware.DefaultCORSConfig(),
		RateLimitPerMinute: 100000,
		RequestTimeout:     30 * time.Second,
		MetricsEnabled:     false,
	}

	return api.NewRouter(config, h)
}

func generateBenchToken(role string) string {
	claims := middleware.UserClaims{
		UserID:   "00000000-0000-0000-0000-000000000001",
		Username: "benchmark-user",
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "usulnet-bench",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, _ := token.SignedString([]byte(benchJWTSecret))
	return tokenString
}

// BenchmarkHealthEndpoint measures the performance of the /health endpoint.
func BenchmarkHealthEndpoint(b *testing.B) {
	router := setupBenchRouter()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/health", nil)
			router.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status: %d", w.Code)
			}
		}
	})
}

// BenchmarkVersionEndpoint measures the performance of the public version endpoint.
func BenchmarkVersionEndpoint(b *testing.B) {
	router := setupBenchRouter()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/system/version", nil)
			router.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status: %d", w.Code)
			}
		}
	})
}

// BenchmarkAuthenticatedRequest measures the overhead of JWT authentication.
func BenchmarkAuthenticatedRequest(b *testing.B) {
	router := setupBenchRouter()
	token := generateBenchToken("viewer")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/api/v1/system/info", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			router.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status: %d", w.Code)
			}
		}
	})
}

// BenchmarkJWTTokenGeneration measures JWT token creation performance.
func BenchmarkJWTTokenGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		claims := middleware.UserClaims{
			UserID:   "00000000-0000-0000-0000-000000000001",
			Username: "bench-user",
			Role:     "viewer",
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				Issuer:    "usulnet",
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		_, err := token.SignedString([]byte(benchJWTSecret))
		if err != nil {
			b.Fatalf("failed to sign token: %v", err)
		}
	}
}

// BenchmarkJWTTokenValidation measures JWT token validation performance.
func BenchmarkJWTTokenValidation(b *testing.B) {
	tokenStr := generateBenchToken("viewer")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		token, err := jwt.ParseWithClaims(tokenStr, &middleware.UserClaims{}, func(token *jwt.Token) (any, error) {
			return []byte(benchJWTSecret), nil
		})
		if err != nil {
			b.Fatalf("failed to parse token: %v", err)
		}
		if !token.Valid {
			b.Fatal("token is not valid")
		}
	}
}

// BenchmarkJSONSerialization measures JSON response encoding performance.
func BenchmarkJSONSerialization(b *testing.B) {
	data := handlers.HealthResponse{
		Status:  "healthy",
		Version: "1.0.0",
		Uptime:  86400,
		Components: map[string]*handlers.HealthStatus{
			"postgresql": {Status: "up", Latency: 2},
			"redis":      {Status: "up", Latency: 1},
			"nats":       {Status: "up", Latency: 1},
			"docker":     {Status: "up", Latency: 5},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := json.Marshal(data)
		if err != nil {
			b.Fatalf("failed to marshal: %v", err)
		}
	}
}

// BenchmarkJSONDeserialization measures JSON request decoding performance.
func BenchmarkJSONDeserialization(b *testing.B) {
	body := `{"username":"admin","password":"secretpassword123"}`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
			b.Fatalf("failed to decode: %v", err)
		}
	}
}

// BenchmarkPaginatedResponse measures paginated response creation performance.
func BenchmarkPaginatedResponse(b *testing.B) {
	data := make([]map[string]any, 100)
	for i := range data {
		data[i] = map[string]any{
			"id":     i,
			"name":   "container-" + string(rune('a'+i%26)),
			"status": "running",
		}
	}

	params := handlers.PaginationParams{Page: 1, PerPage: 20, Offset: 0}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resp := handlers.NewPaginatedResponse(data, 1000, params)
		_, err := json.Marshal(resp)
		if err != nil {
			b.Fatalf("failed to marshal: %v", err)
		}
	}
}

// BenchmarkHealthWithMultipleCheckers measures health check with many components.
func BenchmarkHealthWithMultipleCheckers(b *testing.B) {
	handler := handlers.NewSystemHandler("1.0.0", "abc123", "2026-01-01", nil)

	components := []string{"postgresql", "redis", "nats", "docker", "scheduler", "gateway", "backup", "security"}
	for _, name := range components {
		handler.RegisterHealthChecker(name, func(ctx context.Context) *handlers.HealthStatus {
			return &handlers.HealthStatus{Status: "up", Latency: 1}
		})
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/health", nil)
			handler.Health(w, r)
			if w.Code != http.StatusOK {
				b.Fatalf("unexpected status: %d", w.Code)
			}
		}
	})
}
