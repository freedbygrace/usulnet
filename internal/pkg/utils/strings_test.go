// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package utils

import (
	"strings"
	"testing"
)

// ============================================================================
// Truncate
// ============================================================================

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"shorter than max", "hello", 10, "hello"},
		{"equal to max", "hello", 5, "hello"},
		{"longer than max", "hello world", 8, "hello..."},
		{"max 3", "hello", 3, "hel"},
		{"max 2", "hello", 2, "he"},
		{"max 1", "hello", 1, "h"},
		{"empty string", "", 5, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Truncate(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("Truncate(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}

// ============================================================================
// TruncateMiddle
// ============================================================================

func TestTruncateMiddle(t *testing.T) {
	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"shorter than max", "hello", 10, "hello"},
		{"equal to max", "hello", 5, "hello"},
		{"max 5", "hello world!", 5, "hello"},
		{"longer string", "abcdefghijklmnop", 10, "abc...nop"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := TruncateMiddle(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("TruncateMiddle(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
			if len(got) > tt.maxLen {
				t.Errorf("TruncateMiddle result length %d exceeds maxLen %d", len(got), tt.maxLen)
			}
		})
	}
}

// ============================================================================
// Slugify
// ============================================================================

func TestSlugify(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want string
	}{
		{"simple", "Hello World", "hello-world"},
		{"underscores", "hello_world", "hello-world"},
		{"special chars", "Hello! World?", "hello-world"},
		{"leading trailing", "  hello  ", "hello"},
		{"consecutive hyphens", "hello---world", "hello-world"},
		{"mixed", "My Docker Stack (v2)", "my-docker-stack-v2"},
		{"numbers", "version 1.2.3", "version-123"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Slugify(tt.s)
			if got != tt.want {
				t.Errorf("Slugify(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

// ============================================================================
// Contains / ContainsIgnoreCase
// ============================================================================

func TestContains(t *testing.T) {
	slice := []string{"apple", "banana", "cherry"}

	if !Contains(slice, "banana") {
		t.Error("Contains should find 'banana'")
	}
	if Contains(slice, "grape") {
		t.Error("Contains should not find 'grape'")
	}
	if Contains(nil, "apple") {
		t.Error("Contains should return false for nil slice")
	}
}

func TestContainsIgnoreCase(t *testing.T) {
	slice := []string{"Apple", "BANANA", "Cherry"}

	if !ContainsIgnoreCase(slice, "apple") {
		t.Error("ContainsIgnoreCase should find 'apple'")
	}
	if !ContainsIgnoreCase(slice, "CHERRY") {
		t.Error("ContainsIgnoreCase should find 'CHERRY'")
	}
	if ContainsIgnoreCase(slice, "grape") {
		t.Error("ContainsIgnoreCase should not find 'grape'")
	}
}

// ============================================================================
// Unique
// ============================================================================

func TestUnique(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  int
	}{
		{"no duplicates", []string{"a", "b", "c"}, 3},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, 3},
		{"all same", []string{"x", "x", "x"}, 1},
		{"empty", []string{}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Unique(tt.input)
			if len(got) != tt.want {
				t.Errorf("Unique() length = %d, want %d", len(got), tt.want)
			}
		})
	}
}

func TestUnique_PreservesOrder(t *testing.T) {
	input := []string{"c", "a", "b", "a", "c"}
	got := Unique(input)
	expected := []string{"c", "a", "b"}

	if len(got) != len(expected) {
		t.Fatalf("length mismatch: got %d, want %d", len(got), len(expected))
	}
	for i, v := range expected {
		if got[i] != v {
			t.Errorf("Unique()[%d] = %q, want %q", i, got[i], v)
		}
	}
}

// ============================================================================
// Filter
// ============================================================================

func TestFilter(t *testing.T) {
	input := []string{"apple", "banana", "avocado", "cherry"}
	got := Filter(input, func(s string) bool {
		return strings.HasPrefix(s, "a")
	})

	if len(got) != 2 {
		t.Fatalf("Filter() length = %d, want 2", len(got))
	}
	if got[0] != "apple" || got[1] != "avocado" {
		t.Errorf("Filter() = %v, want [apple avocado]", got)
	}
}

func TestFilter_NoMatch(t *testing.T) {
	input := []string{"apple", "banana"}
	got := Filter(input, func(s string) bool { return false })
	if len(got) != 0 {
		t.Errorf("Filter() should return empty slice, got %v", got)
	}
}

// ============================================================================
// Map
// ============================================================================

func TestMap(t *testing.T) {
	input := []string{"hello", "world"}
	got := Map(input, strings.ToUpper)

	if len(got) != 2 {
		t.Fatalf("Map() length = %d, want 2", len(got))
	}
	if got[0] != "HELLO" || got[1] != "WORLD" {
		t.Errorf("Map() = %v, want [HELLO WORLD]", got)
	}
}

// ============================================================================
// SplitAndTrim
// ============================================================================

func TestSplitAndTrim(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sep  string
		want int
	}{
		{"normal", "a, b, c", ",", 3},
		{"with whitespace", "  a , b ,  c  ", ",", 3},
		{"empty parts", "a,,b", ",", 2},
		{"all empty", ",,", ",", 0},
		{"single", "hello", ",", 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitAndTrim(tt.s, tt.sep)
			if len(got) != tt.want {
				t.Errorf("SplitAndTrim(%q, %q) length = %d, want %d", tt.s, tt.sep, len(got), tt.want)
			}
		})
	}
}

// ============================================================================
// FirstNonEmpty / DefaultString
// ============================================================================

func TestFirstNonEmpty(t *testing.T) {
	if got := FirstNonEmpty("", "", "hello"); got != "hello" {
		t.Errorf("FirstNonEmpty() = %q, want 'hello'", got)
	}
	if got := FirstNonEmpty("first", "second"); got != "first" {
		t.Errorf("FirstNonEmpty() = %q, want 'first'", got)
	}
	if got := FirstNonEmpty("", ""); got != "" {
		t.Errorf("FirstNonEmpty() = %q, want empty", got)
	}
}

func TestDefaultString(t *testing.T) {
	if got := DefaultString("", "default"); got != "default" {
		t.Errorf("DefaultString() = %q, want 'default'", got)
	}
	if got := DefaultString("value", "default"); got != "value" {
		t.Errorf("DefaultString() = %q, want 'value'", got)
	}
}

// ============================================================================
// IsEmpty / IsNotEmpty
// ============================================================================

func TestIsEmpty(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"", true},
		{"   ", true},
		{"\t\n", true},
		{"hello", false},
		{" hello ", false},
	}

	for _, tt := range tests {
		if got := IsEmpty(tt.s); got != tt.want {
			t.Errorf("IsEmpty(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestIsNotEmpty(t *testing.T) {
	if !IsNotEmpty("hello") {
		t.Error("IsNotEmpty('hello') should be true")
	}
	if IsNotEmpty("   ") {
		t.Error("IsNotEmpty('   ') should be false")
	}
}

// ============================================================================
// PadLeft / PadRight
// ============================================================================

func TestPadLeft(t *testing.T) {
	tests := []struct {
		s      string
		length int
		pad    rune
		want   string
	}{
		{"42", 5, '0', "00042"},
		{"hello", 3, '0', "hello"},
		{"", 3, 'x', "xxx"},
	}

	for _, tt := range tests {
		got := PadLeft(tt.s, tt.length, tt.pad)
		if got != tt.want {
			t.Errorf("PadLeft(%q, %d, %c) = %q, want %q", tt.s, tt.length, tt.pad, got, tt.want)
		}
	}
}

func TestPadRight(t *testing.T) {
	tests := []struct {
		s      string
		length int
		pad    rune
		want   string
	}{
		{"42", 5, '0', "42000"},
		{"hello", 3, '0', "hello"},
		{"", 3, 'x', "xxx"},
	}

	for _, tt := range tests {
		got := PadRight(tt.s, tt.length, tt.pad)
		if got != tt.want {
			t.Errorf("PadRight(%q, %d, %c) = %q, want %q", tt.s, tt.length, tt.pad, got, tt.want)
		}
	}
}

// ============================================================================
// Capitalize
// ============================================================================

func TestCapitalize(t *testing.T) {
	tests := []struct {
		s    string
		want string
	}{
		{"hello", "Hello"},
		{"Hello", "Hello"},
		{"", ""},
		{"a", "A"},
		{"123", "123"},
	}

	for _, tt := range tests {
		got := Capitalize(tt.s)
		if got != tt.want {
			t.Errorf("Capitalize(%q) = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// ============================================================================
// ToCamelCase / ToSnakeCase
// ============================================================================

func TestToCamelCase(t *testing.T) {
	tests := []struct {
		s    string
		want string
	}{
		{"hello-world", "helloWorld"},
		{"hello_world", "helloWorld"},
		{"hello world", "helloWorld"},
		{"HELLO-WORLD", "helloWorld"},
		{"single", "single"},
	}

	for _, tt := range tests {
		got := ToCamelCase(tt.s)
		if got != tt.want {
			t.Errorf("ToCamelCase(%q) = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		s    string
		want string
	}{
		{"helloWorld", "hello_world"},
		{"HelloWorld", "hello_world"},
		{"hello-world", "hello_world"},
		{"hello world", "hello_world"},
		{"already_snake", "already_snake"},
	}

	for _, tt := range tests {
		got := ToSnakeCase(tt.s)
		if got != tt.want {
			t.Errorf("ToSnakeCase(%q) = %q, want %q", tt.s, got, tt.want)
		}
	}
}

// ============================================================================
// MaskString / MaskEmail
// ============================================================================

func TestMaskString(t *testing.T) {
	tests := []struct {
		name         string
		s            string
		visibleStart int
		visibleEnd   int
		want         string
	}{
		{"normal", "secretkey123", 3, 3, "sec******123"},
		{"short string", "ab", 2, 2, "**"},
		{"all masked", "secret", 0, 0, "******"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MaskString(tt.s, tt.visibleStart, tt.visibleEnd)
			if got != tt.want {
				t.Errorf("MaskString(%q, %d, %d) = %q, want %q", tt.s, tt.visibleStart, tt.visibleEnd, got, tt.want)
			}
		})
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		email string
		want  string
	}{
		{"john@example.com", "j**n@example.com"},
		{"alice.smith@test.org", "a*********h@test.org"},
		{"ab@test.com", "ab@test.com"},
		{"no-at-sign", "n********n"},
	}

	for _, tt := range tests {
		got := MaskEmail(tt.email)
		if got != tt.want {
			t.Errorf("MaskEmail(%q) = %q, want %q", tt.email, got, tt.want)
		}
	}
}

// ============================================================================
// RemovePrefix / RemoveSuffix
// ============================================================================

func TestRemovePrefix(t *testing.T) {
	if got := RemovePrefix("hello_world", "hello_"); got != "world" {
		t.Errorf("RemovePrefix() = %q, want 'world'", got)
	}
	if got := RemovePrefix("hello", "xyz"); got != "hello" {
		t.Errorf("RemovePrefix() = %q, want 'hello'", got)
	}
}

func TestRemoveSuffix(t *testing.T) {
	if got := RemoveSuffix("hello.txt", ".txt"); got != "hello" {
		t.Errorf("RemoveSuffix() = %q, want 'hello'", got)
	}
	if got := RemoveSuffix("hello", ".txt"); got != "hello" {
		t.Errorf("RemoveSuffix() = %q, want 'hello'", got)
	}
}

// ============================================================================
// ExtractBetween
// ============================================================================

func TestExtractBetween(t *testing.T) {
	tests := []struct {
		s     string
		start string
		end   string
		want  string
	}{
		{"hello [world] foo", "[", "]", "world"},
		{"<tag>content</tag>", "<tag>", "</tag>", "content"},
		{"no match here", "[", "]", ""},
		{"start only [", "[", "]", ""},
	}

	for _, tt := range tests {
		got := ExtractBetween(tt.s, tt.start, tt.end)
		if got != tt.want {
			t.Errorf("ExtractBetween(%q, %q, %q) = %q, want %q", tt.s, tt.start, tt.end, got, tt.want)
		}
	}
}
