// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package validator

import (
	"testing"
)

// ============================================================================
// New
// ============================================================================

func TestNew(t *testing.T) {
	v := New()
	if v == nil {
		t.Fatal("New() returned nil")
	}
	if v.v == nil {
		t.Fatal("New() returned Validator with nil inner validator")
	}
}

func TestNew_Singleton(t *testing.T) {
	v1 := New()
	v2 := New()
	// Both should use the same underlying validator (sync.Once)
	if v1.v != v2.v {
		t.Error("New() should return Validators sharing the same underlying instance")
	}
}

// ============================================================================
// Validate struct
// ============================================================================

type testStruct struct {
	Name  string `json:"name" validate:"required,min=3,max=50"`
	Email string `json:"email" validate:"required,email"`
	Role  string `json:"role" validate:"required,oneof=admin operator viewer"`
}

func TestValidate_ValidStruct(t *testing.T) {
	v := New()
	s := testStruct{Name: "testuser", Email: "test@example.com", Role: "admin"}

	if err := v.Validate(s); err != nil {
		t.Errorf("Validate() should pass for valid struct, got: %v", err)
	}
}

func TestValidate_MissingRequired(t *testing.T) {
	v := New()
	s := testStruct{} // All fields empty

	if err := v.Validate(s); err == nil {
		t.Error("Validate() should fail for empty required fields")
	}
}

func TestValidate_InvalidEmail(t *testing.T) {
	v := New()
	s := testStruct{Name: "testuser", Email: "not-an-email", Role: "admin"}

	if err := v.Validate(s); err == nil {
		t.Error("Validate() should fail for invalid email")
	}
}

func TestValidate_InvalidRole(t *testing.T) {
	v := New()
	s := testStruct{Name: "testuser", Email: "test@example.com", Role: "superadmin"}

	if err := v.Validate(s); err == nil {
		t.Error("Validate() should fail for invalid role (not in oneof)")
	}
}

func TestValidate_NameTooShort(t *testing.T) {
	v := New()
	s := testStruct{Name: "ab", Email: "test@example.com", Role: "admin"}

	if err := v.Validate(s); err == nil {
		t.Error("Validate() should fail for name shorter than min")
	}
}

// ============================================================================
// ValidateVar
// ============================================================================

func TestValidateVar_Email(t *testing.T) {
	v := New()
	if err := v.ValidateVar("test@example.com", "required,email"); err != nil {
		t.Errorf("ValidateVar should pass for valid email: %v", err)
	}
	if err := v.ValidateVar("not-email", "required,email"); err == nil {
		t.Error("ValidateVar should fail for invalid email")
	}
}

func TestValidateVar_Required(t *testing.T) {
	v := New()
	if err := v.ValidateVar("", "required"); err == nil {
		t.Error("ValidateVar should fail for empty required field")
	}
}

// ============================================================================
// ValidationErrors
// ============================================================================

func TestValidationErrors_ValidInput(t *testing.T) {
	v := New()
	errs := v.ValidationErrors(nil)
	if errs != nil {
		t.Error("ValidationErrors(nil) should return nil")
	}
}

func TestValidationErrors_InvalidInput(t *testing.T) {
	v := New()
	s := testStruct{} // All empty
	err := v.Validate(s)
	if err == nil {
		t.Fatal("expected validation error")
	}

	errs := v.ValidationErrors(err)
	if errs == nil {
		t.Fatal("ValidationErrors should return field errors")
	}

	// Should have errors for name, email, role
	if _, ok := errs["name"]; !ok {
		t.Error("should have error for 'name' field")
	}
	if _, ok := errs["email"]; !ok {
		t.Error("should have error for 'email' field")
	}
	if _, ok := errs["role"]; !ok {
		t.Error("should have error for 'role' field")
	}
}

func TestValidationErrors_NonValidationError(t *testing.T) {
	v := New()
	errs := v.ValidationErrors(errSample)
	if errs == nil {
		t.Fatal("ValidationErrors should return map for non-validation errors")
	}
	if _, ok := errs["_error"]; !ok {
		t.Error("should have _error key for non-validation errors")
	}
}

// ============================================================================
// Custom validations: username
// ============================================================================

type usernameStruct struct {
	Username string `json:"username" validate:"required,username"`
}

func TestCustomValidation_Username(t *testing.T) {
	v := New()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid", "testuser", false},
		{"with underscore", "test_user", false},
		{"with numbers", "user123", false},
		{"min length", "abc", false},
		{"too short", "ab", true},
		{"starts with number", "1user", true},
		{"starts with underscore", "_user", true},
		{"special chars", "user@name", true},
		{"spaces", "user name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := usernameStruct{Username: tt.input}
			err := v.Validate(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("username %q: error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Custom validations: password_strength
// ============================================================================

type passwordStruct struct {
	Password string `json:"password" validate:"required,password_strength"`
}

func TestCustomValidation_PasswordStrength(t *testing.T) {
	v := New()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"strong", "MyP@ssw0rd", false},
		{"just meets requirements", "Abcdefg1", false},
		{"too short", "Ab1!", true},
		{"no uppercase", "abcdefg1", true},
		{"no lowercase", "ABCDEFG1", true},
		{"no digit", "Abcdefgh", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := passwordStruct{Password: tt.input}
			err := v.Validate(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("password %q: error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Custom validations: docker_image
// ============================================================================

type imageStruct struct {
	Image string `json:"image" validate:"required,docker_image"`
}

func TestCustomValidation_DockerImage(t *testing.T) {
	v := New()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "nginx", false},
		{"with tag", "nginx:latest", false},
		{"with registry", "docker.io/nginx:1.25", false},
		{"ghcr", "ghcr.io/user/repo:tag", false},
		{"with sha256", "nginx@sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", false},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := imageStruct{Image: tt.input}
			err := v.Validate(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("image %q: error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Custom validations: docker_container_name
// ============================================================================

type containerNameStruct struct {
	Name string `json:"name" validate:"required,docker_container_name"`
}

func TestCustomValidation_DockerContainerName(t *testing.T) {
	v := New()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"simple", "mycontainer", false},
		{"with dots", "my.container", false},
		{"with dashes", "my-container", false},
		{"with underscores", "my_container", false},
		{"starts with number", "1container", false},
		{"starts with dash", "-container", true},
		{"spaces", "my container", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := containerNameStruct{Name: tt.input}
			err := v.Validate(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("container name %q: error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Custom validations: cron
// ============================================================================

type cronStruct struct {
	Cron string `json:"cron" validate:"required,cron"`
}

func TestCustomValidation_Cron(t *testing.T) {
	v := New()

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"5 fields", "0 * * * *", false},
		{"6 fields", "0 0 * * * *", false},
		{"daily", "0 0 * * *", false},
		{"too few fields", "* *", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := cronStruct{Cron: tt.input}
			err := v.Validate(s)
			if (err != nil) != tt.wantErr {
				t.Errorf("cron %q: error = %v, wantErr = %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

// ============================================================================
// Custom validations: hexstring / base64 / port
// ============================================================================

type hexStruct struct {
	Hex string `json:"hex" validate:"required,hexstring"`
}

func TestCustomValidation_HexString(t *testing.T) {
	v := New()

	valid := hexStruct{Hex: "abcdef0123456789"}
	if err := v.Validate(valid); err != nil {
		t.Errorf("valid hex should pass: %v", err)
	}

	invalid := hexStruct{Hex: "xyz123"}
	if err := v.Validate(invalid); err == nil {
		t.Error("invalid hex should fail")
	}
}

type portStruct struct {
	Port int `json:"port" validate:"required,port"`
}

func TestCustomValidation_Port(t *testing.T) {
	v := New()

	tests := []struct {
		port    int
		wantErr bool
	}{
		{80, false},
		{443, false},
		{8080, false},
		{65535, false},
		{1, false},
		{0, true},
		{65536, true},
		{-1, true},
	}

	for _, tt := range tests {
		s := portStruct{Port: tt.port}
		err := v.Validate(s)
		if (err != nil) != tt.wantErr {
			t.Errorf("port %d: error = %v, wantErr = %v", tt.port, err, tt.wantErr)
		}
	}
}

// ============================================================================
// Global convenience functions
// ============================================================================

func TestGlobalValidate(t *testing.T) {
	s := testStruct{Name: "test", Email: "test@example.com", Role: "admin"}
	if err := Validate(s); err != nil {
		t.Errorf("global Validate() should pass: %v", err)
	}
}

func TestGlobalValidateVar(t *testing.T) {
	if err := ValidateVar("test@example.com", "email"); err != nil {
		t.Errorf("global ValidateVar() should pass for valid email: %v", err)
	}
}

func TestGetValidationErrors(t *testing.T) {
	s := testStruct{} // all empty
	err := Validate(s)
	if err == nil {
		t.Fatal("expected error")
	}
	errs := GetValidationErrors(err)
	if errs == nil {
		t.Fatal("GetValidationErrors should return errors")
	}
}

// ============================================================================
// formatValidationError coverage
// ============================================================================

func TestFormatValidationError_Messages(t *testing.T) {
	v := New()

	// Test various validation tags produce meaningful messages
	type testInput struct {
		Required string `json:"required" validate:"required"`
		Email    string `json:"email" validate:"email"`
		Min      string `json:"min" validate:"min=3"`
		Max      string `json:"max" validate:"max=5"`
		OneOf    string `json:"oneof" validate:"oneof=a b c"`
	}

	s := testInput{Min: "a", Max: "toolong", OneOf: "x"}
	err := v.Validate(s)
	if err == nil {
		t.Fatal("expected validation error")
	}

	errs := v.ValidationErrors(err)
	if errs == nil {
		t.Fatal("ValidationErrors should return map")
	}

	// Check that error messages are human-readable
	if msg, ok := errs["required"]; ok {
		if msg != "is required" {
			t.Errorf("required error = %q, want 'is required'", msg)
		}
	}
}

// sample error for testing
var errSample = &sampleError{}

type sampleError struct{}

func (e *sampleError) Error() string { return "sample error" }
