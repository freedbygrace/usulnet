// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"testing"
)

// ============================================================================
// Policy presets
// ============================================================================

func TestDefaultPasswordPolicy(t *testing.T) {
	p := DefaultPasswordPolicy()

	if p.MinLength != 8 {
		t.Errorf("MinLength = %d, want 8", p.MinLength)
	}
	if p.MaxLength != 128 {
		t.Errorf("MaxLength = %d, want 128", p.MaxLength)
	}
	if !p.RequireUppercase {
		t.Error("RequireUppercase should be true")
	}
	if !p.RequireLowercase {
		t.Error("RequireLowercase should be true")
	}
	if !p.RequireNumber {
		t.Error("RequireNumber should be true")
	}
	if p.RequireSpecial {
		t.Error("RequireSpecial should be false by default")
	}
	if !p.DisallowUsername {
		t.Error("DisallowUsername should be true")
	}
	if !p.DisallowCommonPasswords {
		t.Error("DisallowCommonPasswords should be true")
	}
	if p.MaxConsecutiveChars != 3 {
		t.Errorf("MaxConsecutiveChars = %d, want 3", p.MaxConsecutiveChars)
	}
}

func TestStrictPasswordPolicy(t *testing.T) {
	p := StrictPasswordPolicy()

	if p.MinLength != 12 {
		t.Errorf("MinLength = %d, want 12", p.MinLength)
	}
	if !p.RequireSpecial {
		t.Error("Strict policy should require special chars")
	}
	if p.MinSpecial != 1 {
		t.Errorf("MinSpecial = %d, want 1", p.MinSpecial)
	}
}

func TestMinimalPasswordPolicy(t *testing.T) {
	p := MinimalPasswordPolicy()

	if p.MinLength != 8 {
		t.Errorf("MinLength = %d, want 8", p.MinLength)
	}
	if p.RequireUppercase {
		t.Error("Minimal should not require uppercase")
	}
	if p.RequireLowercase {
		t.Error("Minimal should not require lowercase")
	}
	if p.RequireNumber {
		t.Error("Minimal should not require numbers")
	}
	if p.DisallowCommonPasswords {
		t.Error("Minimal should not disallow common passwords")
	}
	if p.MaxConsecutiveChars != 0 {
		t.Error("Minimal should not check consecutive chars")
	}
}

// ============================================================================
// ValidatePassword - Default policy
// ============================================================================

func TestValidatePassword_StrongPassword(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("MyStr0ng!Pass", "testuser")

	if !result.Valid {
		t.Errorf("strong password should be valid, errors: %v", result.Errors)
	}
	if result.Score < 50 {
		t.Errorf("strong password score = %d, want >= 50", result.Score)
	}
}

func TestValidatePassword_TooShort(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("Ab1", "user")

	if result.Valid {
		t.Error("short password should be invalid")
	}
}

func TestValidatePassword_TooLong(t *testing.T) {
	p := DefaultPasswordPolicy()
	long := make([]byte, 130)
	for i := range long {
		long[i] = 'A'
	}
	result := p.ValidatePassword(string(long), "user")

	if result.Valid {
		t.Error("password exceeding MaxLength should be invalid")
	}
}

func TestValidatePassword_NoUppercase(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("nouppercase123", "user")

	if result.Valid {
		t.Error("password without uppercase should be invalid (default policy)")
	}
}

func TestValidatePassword_NoLowercase(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("NOLOWERCASE123", "user")

	if result.Valid {
		t.Error("password without lowercase should be invalid (default policy)")
	}
}

func TestValidatePassword_NoNumber(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("NoNumberHere!", "user")

	if result.Valid {
		t.Error("password without number should be invalid (default policy)")
	}
}

func TestValidatePassword_ContainsUsername(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("Testuser123!", "testuser")

	if result.Valid {
		t.Error("password containing username should be invalid")
	}
}

func TestValidatePassword_ContainsUsername_CaseInsensitive(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("TESTUSER123!abc", "testuser")

	if result.Valid {
		t.Error("password containing username (case-insensitive) should be invalid")
	}
}

func TestValidatePassword_ConsecutiveChars(t *testing.T) {
	p := DefaultPasswordPolicy()
	result := p.ValidatePassword("Passsss1word", "user")

	if result.Valid {
		t.Error("password with too many consecutive chars should be invalid")
	}
}

func TestValidatePassword_CommonPassword(t *testing.T) {
	p := DefaultPasswordPolicy()
	commonPasswords := []string{
		"password", "12345678", "qwerty123", "admin123",
		"password1", "password123", "welcome1",
	}

	for _, pw := range commonPasswords {
		result := p.ValidatePassword(pw, "")
		if result.Valid {
			t.Errorf("common password %q should be invalid", pw)
		}
	}
}

// ============================================================================
// ValidatePassword - Strict policy
// ============================================================================

func TestValidatePassword_Strict_RequiresSpecial(t *testing.T) {
	p := StrictPasswordPolicy()
	result := p.ValidatePassword("MyPassword123", "user")

	if result.Valid {
		t.Error("strict policy should require special character")
	}
}

func TestValidatePassword_Strict_FullyCompliant(t *testing.T) {
	p := StrictPasswordPolicy()
	result := p.ValidatePassword("MyStr0ng!P@ss", "user")

	if !result.Valid {
		t.Errorf("fully compliant strict password should be valid, errors: %v", result.Errors)
	}
}

// ============================================================================
// ValidatePassword - Minimal policy
// ============================================================================

func TestValidatePassword_Minimal_JustLength(t *testing.T) {
	p := MinimalPasswordPolicy()
	result := p.ValidatePassword("abcdefgh", "")

	if !result.Valid {
		t.Errorf("minimal policy should only check length, errors: %v", result.Errors)
	}
}

func TestValidatePassword_Minimal_TooShort(t *testing.T) {
	p := MinimalPasswordPolicy()
	result := p.ValidatePassword("short", "")

	if result.Valid {
		t.Error("even minimal policy should reject too-short passwords")
	}
}

// ============================================================================
// Score
// ============================================================================

func TestValidatePassword_ScoreCalculation(t *testing.T) {
	p := DefaultPasswordPolicy()

	// Long password with all character types: high score
	result := p.ValidatePassword("MyV3ryStr0ng!P@ssw0rd", "user")
	if result.Score < 80 {
		t.Errorf("very strong password score = %d, want >= 80", result.Score)
	}

	// Score should be capped at 100
	if result.Score > 100 {
		t.Errorf("score = %d, should be capped at 100", result.Score)
	}
}

func TestValidatePassword_WeakPasswordWarning(t *testing.T) {
	p := MinimalPasswordPolicy()
	result := p.ValidatePassword("abcdefgh", "")

	if result.Score >= 50 {
		t.Errorf("weak password score = %d, want < 50", result.Score)
	}
	if len(result.Warnings) == 0 {
		t.Error("weak password should have warnings")
	}
}

// ============================================================================
// GetPasswordStrengthLabel
// ============================================================================

func TestGetPasswordStrengthLabel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "Strong"},
		{80, "Strong"},
		{70, "Good"},
		{60, "Good"},
		{50, "Fair"},
		{40, "Fair"},
		{30, "Weak"},
		{20, "Weak"},
		{10, "Very Weak"},
		{0, "Very Weak"},
	}

	for _, tt := range tests {
		got := GetPasswordStrengthLabel(tt.score)
		if got != tt.want {
			t.Errorf("GetPasswordStrengthLabel(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ============================================================================
// checkConsecutive (internal)
// ============================================================================

func TestCheckConsecutive(t *testing.T) {
	tests := []struct {
		password  string
		maxConsec int
		want      bool
	}{
		{"aaa", 3, false},    // exactly 3, not more
		{"aaaa", 3, true},    // more than 3
		{"aabbb", 3, false},  // 3 consecutive, not more
		{"aabbbb", 3, true},  // 4 consecutive
		{"abcdef", 3, false}, // no consecutive
		{"", 3, false},
	}

	for _, tt := range tests {
		got := checkConsecutive(tt.password, tt.maxConsec)
		if got != tt.want {
			t.Errorf("checkConsecutive(%q, %d) = %v, want %v", tt.password, tt.maxConsec, got, tt.want)
		}
	}
}

func TestCheckConsecutive_ZeroMaxConsec(t *testing.T) {
	got := checkConsecutive("aaaa", 0)
	if got {
		t.Error("checkConsecutive with maxConsec=0 should return false (no limit)")
	}
}
