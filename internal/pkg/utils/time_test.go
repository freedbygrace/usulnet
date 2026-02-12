// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package utils

import (
	"testing"
	"time"
)

// ============================================================================
// Now / NowPtr
// ============================================================================

func TestNow(t *testing.T) {
	before := time.Now().UTC()
	got := Now()
	after := time.Now().UTC()

	if got.Before(before) || got.After(after) {
		t.Error("Now() should return current UTC time")
	}
	if got.Location() != time.UTC {
		t.Error("Now() should return UTC time")
	}
}

func TestNowPtr(t *testing.T) {
	ptr := NowPtr()
	if ptr == nil {
		t.Fatal("NowPtr() should not return nil")
	}
}

// ============================================================================
// ParseTime
// ============================================================================

func TestParseTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"RFC3339", "2024-01-15T10:30:00Z", false},
		{"RFC3339Nano", "2024-01-15T10:30:00.123456789Z", false},
		{"DateTime", "2024-01-15 10:30:00", false},
		{"DateOnly", "2024-01-15", false},
		{"ISO without Z", "2024-01-15T10:30:00", false},
		{"ISO with Z", "2024-01-15T10:30:00Z", false},
		{"Slash date", "2024/01/15", false},
		{"Invalid", "not a date", true},
		{"Empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTime(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTime(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestParseTime_ReturnsUTC(t *testing.T) {
	parsed, err := ParseTime("2024-01-15T10:30:00Z")
	if err != nil {
		t.Fatalf("ParseTime() error: %v", err)
	}
	if parsed.Location() != time.UTC {
		t.Error("ParseTime should return UTC time")
	}
}

// ============================================================================
// FormatDuration
// ============================================================================

func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"milliseconds", 500 * time.Millisecond, "500ms"},
		{"seconds", 5 * time.Second, "5.0s"},
		{"minutes only", 5 * time.Minute, "5m"},
		{"minutes and seconds", 5*time.Minute + 30*time.Second, "5m 30s"},
		{"hours only", 2 * time.Hour, "2h"},
		{"hours and minutes", 2*time.Hour + 15*time.Minute, "2h 15m"},
		{"days only", 48 * time.Hour, "2d"},
		{"days and hours", 50 * time.Hour, "2d 2h"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatDuration(tt.d)
			if got != tt.want {
				t.Errorf("FormatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

// ============================================================================
// TimeAgo
// ============================================================================

func TestTimeAgo(t *testing.T) {
	tests := []struct {
		name string
		ago  time.Duration
		want string
	}{
		{"just now", 10 * time.Second, "just now"},
		{"1 minute", 1 * time.Minute, "1 minute ago"},
		{"5 minutes", 5 * time.Minute, "5 minutes ago"},
		{"1 hour", 1 * time.Hour, "1 hour ago"},
		{"3 hours", 3 * time.Hour, "3 hours ago"},
		{"1 day", 24 * time.Hour, "1 day ago"},
		{"3 days", 3 * 24 * time.Hour, "3 days ago"},
		{"1 week", 7 * 24 * time.Hour, "1 week ago"},
		{"3 weeks", 21 * 24 * time.Hour, "3 weeks ago"},
		{"1 month", 35 * 24 * time.Hour, "1 month ago"},
		{"6 months", 180 * 24 * time.Hour, "6 months ago"},
		{"1 year", 365 * 24 * time.Hour, "1 year ago"},
		{"2 years", 730 * 24 * time.Hour, "2 years ago"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TimeAgo(time.Now().Add(-tt.ago))
			if got != tt.want {
				t.Errorf("TimeAgo(-%v) = %q, want %q", tt.ago, got, tt.want)
			}
		})
	}
}

// ============================================================================
// StartOfDay / EndOfDay
// ============================================================================

func TestStartOfDay(t *testing.T) {
	input := time.Date(2024, 6, 15, 14, 30, 45, 123456789, time.UTC)
	got := StartOfDay(input)

	if got.Hour() != 0 || got.Minute() != 0 || got.Second() != 0 || got.Nanosecond() != 0 {
		t.Errorf("StartOfDay() = %v, want midnight", got)
	}
	if got.Year() != 2024 || got.Month() != 6 || got.Day() != 15 {
		t.Errorf("StartOfDay() changed the date")
	}
}

func TestEndOfDay(t *testing.T) {
	input := time.Date(2024, 6, 15, 14, 30, 45, 0, time.UTC)
	got := EndOfDay(input)

	if got.Hour() != 23 || got.Minute() != 59 || got.Second() != 59 {
		t.Errorf("EndOfDay() = %v, want 23:59:59", got)
	}
	if got.Year() != 2024 || got.Month() != 6 || got.Day() != 15 {
		t.Errorf("EndOfDay() changed the date")
	}
}

// ============================================================================
// StartOfWeek
// ============================================================================

func TestStartOfWeek(t *testing.T) {
	// Wednesday June 12, 2024
	input := time.Date(2024, 6, 12, 14, 30, 0, 0, time.UTC)
	got := StartOfWeek(input)

	// Should be Monday June 10, 2024
	if got.Weekday() != time.Monday {
		t.Errorf("StartOfWeek() weekday = %s, want Monday", got.Weekday())
	}
	if got.Day() != 10 {
		t.Errorf("StartOfWeek() day = %d, want 10", got.Day())
	}
}

func TestStartOfWeek_Sunday(t *testing.T) {
	// Sunday June 16, 2024
	input := time.Date(2024, 6, 16, 14, 30, 0, 0, time.UTC)
	got := StartOfWeek(input)

	if got.Weekday() != time.Monday {
		t.Errorf("StartOfWeek(Sunday) weekday = %s, want Monday", got.Weekday())
	}
	if got.Day() != 10 {
		t.Errorf("StartOfWeek(Sunday) day = %d, want 10", got.Day())
	}
}

func TestStartOfWeek_Monday(t *testing.T) {
	// Monday June 10, 2024
	input := time.Date(2024, 6, 10, 14, 30, 0, 0, time.UTC)
	got := StartOfWeek(input)

	if got.Day() != 10 {
		t.Errorf("StartOfWeek(Monday) day = %d, want 10", got.Day())
	}
}

// ============================================================================
// StartOfMonth / EndOfMonth
// ============================================================================

func TestStartOfMonth(t *testing.T) {
	input := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC)
	got := StartOfMonth(input)

	if got.Day() != 1 || got.Hour() != 0 {
		t.Errorf("StartOfMonth() = %v, want June 1 00:00", got)
	}
}

func TestEndOfMonth(t *testing.T) {
	// June has 30 days
	input := time.Date(2024, 6, 15, 14, 30, 0, 0, time.UTC)
	got := EndOfMonth(input)

	if got.Day() != 30 {
		t.Errorf("EndOfMonth(June) day = %d, want 30", got.Day())
	}
}

func TestEndOfMonth_February(t *testing.T) {
	// February 2024 (leap year) has 29 days
	input := time.Date(2024, 2, 10, 0, 0, 0, 0, time.UTC)
	got := EndOfMonth(input)

	if got.Day() != 29 {
		t.Errorf("EndOfMonth(Feb 2024 leap) day = %d, want 29", got.Day())
	}
}

// ============================================================================
// DaysBetween
// ============================================================================

func TestDaysBetween(t *testing.T) {
	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 1, 11, 0, 0, 0, 0, time.UTC)

	if got := DaysBetween(t1, t2); got != 10 {
		t.Errorf("DaysBetween() = %d, want 10", got)
	}
}

func TestDaysBetween_SameDay(t *testing.T) {
	t1 := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if got := DaysBetween(t1, t1); got != 0 {
		t.Errorf("DaysBetween(same day) = %d, want 0", got)
	}
}

// ============================================================================
// IsExpired / IsExpiredWithGrace
// ============================================================================

func TestIsExpired(t *testing.T) {
	past := time.Now().Add(-1 * time.Hour)
	if !IsExpired(past) {
		t.Error("IsExpired should return true for past time")
	}

	future := time.Now().Add(1 * time.Hour)
	if IsExpired(future) {
		t.Error("IsExpired should return false for future time")
	}
}

func TestIsExpiredWithGrace(t *testing.T) {
	// Expired 30 minutes ago, grace period 1 hour
	expired := time.Now().Add(-30 * time.Minute)
	if IsExpiredWithGrace(expired, 1*time.Hour) {
		t.Error("IsExpiredWithGrace should return false when within grace period")
	}

	// Expired 2 hours ago, grace period 1 hour
	longExpired := time.Now().Add(-2 * time.Hour)
	if !IsExpiredWithGrace(longExpired, 1*time.Hour) {
		t.Error("IsExpiredWithGrace should return true when past grace period")
	}
}

// ============================================================================
// TimePtr / TimeValue / DurationPtr / DurationValue
// ============================================================================

func TestTimePtr(t *testing.T) {
	now := time.Now()
	ptr := TimePtr(now)
	if ptr == nil {
		t.Fatal("TimePtr should not return nil")
	}
	if !ptr.Equal(now) {
		t.Error("TimePtr should preserve the time value")
	}
}

func TestTimeValue(t *testing.T) {
	now := time.Now()
	if got := TimeValue(&now); !got.Equal(now) {
		t.Error("TimeValue should return the time value")
	}
	if got := TimeValue(nil); !got.IsZero() {
		t.Error("TimeValue(nil) should return zero time")
	}
}

func TestDurationPtr(t *testing.T) {
	d := 5 * time.Minute
	ptr := DurationPtr(d)
	if ptr == nil {
		t.Fatal("DurationPtr should not return nil")
	}
	if *ptr != d {
		t.Error("DurationPtr should preserve the duration value")
	}
}

func TestDurationValue(t *testing.T) {
	d := 5 * time.Minute
	if got := DurationValue(&d); got != d {
		t.Errorf("DurationValue() = %v, want %v", got, d)
	}
	if got := DurationValue(nil); got != 0 {
		t.Errorf("DurationValue(nil) = %v, want 0", got)
	}
}

// ============================================================================
// ParseDurationWithDays
// ============================================================================

func TestParseDurationWithDays(t *testing.T) {
	tests := []struct {
		name    string
		s       string
		want    time.Duration
		wantErr bool
	}{
		{"days only", "7d", 7 * 24 * time.Hour, false},
		{"1 day", "1d", 24 * time.Hour, false},
		{"standard duration", "2h30m", 2*time.Hour + 30*time.Minute, false},
		{"seconds", "90s", 90 * time.Second, false},
		{"invalid", "xyz", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseDurationWithDays(tt.s)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDurationWithDays(%q) error = %v, wantErr %v", tt.s, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseDurationWithDays(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Constants
// ============================================================================

func TestTimeFormatConstants(t *testing.T) {
	if DateFormat != "2006-01-02" {
		t.Errorf("DateFormat = %q, want '2006-01-02'", DateFormat)
	}
	if TimeFormat != "15:04:05" {
		t.Errorf("TimeFormat = %q, want '15:04:05'", TimeFormat)
	}
	if DateTimeFormat != "2006-01-02 15:04:05" {
		t.Errorf("DateTimeFormat = %q, want '2006-01-02 15:04:05'", DateTimeFormat)
	}
}
