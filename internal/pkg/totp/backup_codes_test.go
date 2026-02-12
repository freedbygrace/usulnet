// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package totp

import (
	"strings"
	"testing"
)

// ============================================================================
// GenerateBackupCodes
// ============================================================================

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes(DefaultBackupCodeCount)
	if err != nil {
		t.Fatalf("GenerateBackupCodes() error: %v", err)
	}
	if len(codes.Codes) != DefaultBackupCodeCount {
		t.Errorf("code count = %d, want %d", len(codes.Codes), DefaultBackupCodeCount)
	}
}

func TestGenerateBackupCodes_DefaultCount(t *testing.T) {
	codes, err := GenerateBackupCodes(0)
	if err != nil {
		t.Fatalf("GenerateBackupCodes(0) error: %v", err)
	}
	if len(codes.Codes) != DefaultBackupCodeCount {
		t.Errorf("default count = %d, want %d", len(codes.Codes), DefaultBackupCodeCount)
	}
}

func TestGenerateBackupCodes_CustomCount(t *testing.T) {
	codes, err := GenerateBackupCodes(5)
	if err != nil {
		t.Fatalf("GenerateBackupCodes(5) error: %v", err)
	}
	if len(codes.Codes) != 5 {
		t.Errorf("count = %d, want 5", len(codes.Codes))
	}
}

func TestGenerateBackupCodes_Format(t *testing.T) {
	codes, _ := GenerateBackupCodes(1)
	code := codes.Codes[0]

	// Code should be formatted as XXXX-XXXX (uppercase hex)
	if !strings.Contains(code.Code, "-") {
		t.Errorf("code should be formatted with dash, got: %s", code.Code)
	}
	if code.Code != strings.ToUpper(code.Code) {
		t.Errorf("code should be uppercase, got: %s", code.Code)
	}
}

func TestGenerateBackupCodes_AllUnused(t *testing.T) {
	codes, _ := GenerateBackupCodes(10)
	for i, code := range codes.Codes {
		if code.Used {
			t.Errorf("code %d should not be used", i)
		}
	}
}

func TestGenerateBackupCodes_HasHashes(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)
	for i, code := range codes.Codes {
		if code.CodeHash == "" {
			t.Errorf("code %d hash should not be empty", i)
		}
		// Hash should be bcrypt format
		if !strings.HasPrefix(code.CodeHash, "$2") {
			t.Errorf("code %d hash should be bcrypt format, got: %s", i, code.CodeHash[:10])
		}
	}
}

func TestGenerateBackupCodes_Unique(t *testing.T) {
	codes, _ := GenerateBackupCodes(10)
	seen := make(map[string]bool)
	for _, code := range codes.Codes {
		if seen[code.Code] {
			t.Errorf("duplicate backup code: %s", code.Code)
		}
		seen[code.Code] = true
	}
}

// ============================================================================
// ValidateBackupCode
// ============================================================================

func TestValidateBackupCode_Valid(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)

	// Take the first code (plaintext) and validate against all hashes
	plainCode := codes.Codes[0].Code
	idx := ValidateBackupCode(plainCode, codes.Codes)

	if idx != 0 {
		t.Errorf("ValidateBackupCode() = %d, want 0", idx)
	}
}

func TestValidateBackupCode_WithoutDash(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)

	// Remove the dash from the code
	plainCode := strings.ReplaceAll(codes.Codes[0].Code, "-", "")
	idx := ValidateBackupCode(plainCode, codes.Codes)

	if idx != 0 {
		t.Errorf("ValidateBackupCode(no dash) = %d, want 0", idx)
	}
}

func TestValidateBackupCode_CaseInsensitive(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)

	// Use lowercase version
	plainCode := strings.ToLower(codes.Codes[0].Code)
	idx := ValidateBackupCode(plainCode, codes.Codes)

	if idx != 0 {
		t.Errorf("ValidateBackupCode(lowercase) = %d, want 0", idx)
	}
}

func TestValidateBackupCode_Invalid(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)

	idx := ValidateBackupCode("XXXX-XXXX", codes.Codes)
	if idx != -1 {
		t.Errorf("ValidateBackupCode(invalid) = %d, want -1", idx)
	}
}

func TestValidateBackupCode_SkipsUsedCodes(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)

	// Mark first code as used
	codes.Codes[0].Used = true
	plainCode := codes.Codes[0].Code

	idx := ValidateBackupCode(plainCode, codes.Codes)
	if idx != -1 {
		t.Errorf("ValidateBackupCode(used) = %d, want -1", idx)
	}
}

// ============================================================================
// ValidateBackupCodeSimple
// ============================================================================

func TestValidateBackupCodeSimple_Valid(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)
	hashes := codes.GetCodeHashes()
	usedFlags := make([]bool, len(hashes))

	valid, idx := ValidateBackupCodeSimple(codes.Codes[2].Code, hashes, usedFlags)
	if !valid || idx != 2 {
		t.Errorf("ValidateBackupCodeSimple() = (%v, %d), want (true, 2)", valid, idx)
	}
}

func TestValidateBackupCodeSimple_MismatchedLengths(t *testing.T) {
	valid, idx := ValidateBackupCodeSimple("XXXX-XXXX", []string{"hash1"}, []bool{false, false})
	if valid || idx != -1 {
		t.Error("should return (false, -1) for mismatched lengths")
	}
}

// ============================================================================
// BackupCodes methods
// ============================================================================

func TestBackupCodes_GetPlaintextCodes(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)
	plaintext := codes.GetPlaintextCodes()

	if len(plaintext) != 5 {
		t.Errorf("GetPlaintextCodes() length = %d, want 5", len(plaintext))
	}
	for i, pt := range plaintext {
		if pt != codes.Codes[i].Code {
			t.Errorf("GetPlaintextCodes()[%d] = %q, want %q", i, pt, codes.Codes[i].Code)
		}
	}
}

func TestBackupCodes_GetCodeHashes(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)
	hashes := codes.GetCodeHashes()

	if len(hashes) != 5 {
		t.Errorf("GetCodeHashes() length = %d, want 5", len(hashes))
	}
	for i, h := range hashes {
		if h != codes.Codes[i].CodeHash {
			t.Errorf("GetCodeHashes()[%d] mismatch", i)
		}
	}
}

func TestBackupCodes_GetRemainingCount(t *testing.T) {
	codes, _ := GenerateBackupCodes(5)

	if codes.GetRemainingCount() != 5 {
		t.Errorf("initial remaining = %d, want 5", codes.GetRemainingCount())
	}

	codes.Codes[0].Used = true
	codes.Codes[2].Used = true
	if codes.GetRemainingCount() != 3 {
		t.Errorf("after using 2, remaining = %d, want 3", codes.GetRemainingCount())
	}
}

// ============================================================================
// HashBackupCode / CompareBackupCode
// ============================================================================

func TestHashBackupCode(t *testing.T) {
	hash, err := HashBackupCode("ABCD-1234")
	if err != nil {
		t.Fatalf("HashBackupCode() error: %v", err)
	}
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash should be bcrypt format, got: %s", hash[:10])
	}
}

func TestCompareBackupCode(t *testing.T) {
	code := "ABCD-1234"
	hash, _ := HashBackupCode(code)

	if !CompareBackupCode(code, hash) {
		t.Error("CompareBackupCode should return true for matching code")
	}
	if !CompareBackupCode("abcd-1234", hash) {
		t.Error("CompareBackupCode should be case-insensitive")
	}
	if !CompareBackupCode("ABCD1234", hash) {
		t.Error("CompareBackupCode should work without dash")
	}
	if CompareBackupCode("WXYZ-5678", hash) {
		t.Error("CompareBackupCode should return false for wrong code")
	}
}

// ============================================================================
// ConstantTimeCompare
// ============================================================================

func TestConstantTimeCompare(t *testing.T) {
	if !ConstantTimeCompare("hello", "hello") {
		t.Error("ConstantTimeCompare should return true for equal strings")
	}
	if ConstantTimeCompare("hello", "world") {
		t.Error("ConstantTimeCompare should return false for different strings")
	}
	if ConstantTimeCompare("hello", "hell") {
		t.Error("ConstantTimeCompare should return false for different lengths")
	}
}

// ============================================================================
// Constants
// ============================================================================

func TestBackupCodeConstants(t *testing.T) {
	if DefaultBackupCodeCount != 10 {
		t.Errorf("DefaultBackupCodeCount = %d, want 10", DefaultBackupCodeCount)
	}
	if BackupCodeLength != 8 {
		t.Errorf("BackupCodeLength = %d, want 8", BackupCodeLength)
	}
}
