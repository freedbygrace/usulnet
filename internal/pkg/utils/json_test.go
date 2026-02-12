// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package utils

import (
	"bytes"
	"strings"
	"testing"
)

// ============================================================================
// MustMarshal / MustMarshalIndent
// ============================================================================

func TestMustMarshal(t *testing.T) {
	data := MustMarshal(map[string]string{"key": "value"})
	if !strings.Contains(string(data), "key") {
		t.Errorf("MustMarshal() = %s, expected to contain 'key'", data)
	}
}

func TestMustMarshal_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustMarshal should panic on unmarshalable value")
		}
	}()
	MustMarshal(make(chan int))
}

func TestMustMarshalIndent(t *testing.T) {
	data := MustMarshalIndent(map[string]string{"key": "value"})
	if !strings.Contains(string(data), "\n") {
		t.Error("MustMarshalIndent should produce indented output")
	}
}

func TestMustMarshalIndent_Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustMarshalIndent should panic on unmarshalable value")
		}
	}()
	MustMarshalIndent(make(chan int))
}

// ============================================================================
// MarshalString / MustMarshalString / UnmarshalString
// ============================================================================

func TestMarshalString(t *testing.T) {
	s, err := MarshalString(map[string]int{"count": 42})
	if err != nil {
		t.Fatalf("MarshalString() error: %v", err)
	}
	if !strings.Contains(s, "42") {
		t.Errorf("MarshalString() = %q, expected to contain '42'", s)
	}
}

func TestMarshalString_Error(t *testing.T) {
	_, err := MarshalString(make(chan int))
	if err == nil {
		t.Error("MarshalString should error for unmarshalable value")
	}
}

func TestMustMarshalString(t *testing.T) {
	s := MustMarshalString(42)
	if s != "42" {
		t.Errorf("MustMarshalString(42) = %q, want '42'", s)
	}
}

func TestUnmarshalString(t *testing.T) {
	var result map[string]string
	err := UnmarshalString(`{"key":"value"}`, &result)
	if err != nil {
		t.Fatalf("UnmarshalString() error: %v", err)
	}
	if result["key"] != "value" {
		t.Errorf("result[key] = %q, want 'value'", result["key"])
	}
}

func TestUnmarshalString_Error(t *testing.T) {
	var result map[string]string
	err := UnmarshalString("not json", &result)
	if err == nil {
		t.Error("UnmarshalString should error for invalid JSON")
	}
}

// ============================================================================
// Clone / MustClone
// ============================================================================

func TestClone(t *testing.T) {
	type data struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	orig := data{Name: "test", Count: 5}
	cloned, err := Clone(orig)
	if err != nil {
		t.Fatalf("Clone() error: %v", err)
	}
	if cloned.Name != orig.Name || cloned.Count != orig.Count {
		t.Errorf("Clone() = %+v, want %+v", cloned, orig)
	}
}

func TestClone_DeepCopy(t *testing.T) {
	orig := map[string]interface{}{
		"items": []interface{}{1, 2, 3},
	}
	cloned, err := Clone(orig)
	if err != nil {
		t.Fatalf("Clone() error: %v", err)
	}

	// Modify original should not affect clone
	orig["items"] = []interface{}{99}
	items := cloned["items"].([]interface{})
	if len(items) != 3 {
		t.Error("Clone should produce a deep copy")
	}
}

func TestMustClone(t *testing.T) {
	orig := map[string]string{"key": "value"}
	cloned := MustClone(orig)
	if cloned["key"] != "value" {
		t.Errorf("MustClone() key = %q, want 'value'", cloned["key"])
	}
}

// ============================================================================
// PrettyPrint / Compact
// ============================================================================

func TestPrettyPrint(t *testing.T) {
	s := PrettyPrint(map[string]int{"a": 1})
	if !strings.Contains(s, "\n") {
		t.Error("PrettyPrint should produce multi-line output")
	}
}

func TestPrettyPrint_Unmarshalable(t *testing.T) {
	s := PrettyPrint(make(chan int))
	if s != "" {
		t.Errorf("PrettyPrint of unmarshalable should return empty, got %q", s)
	}
}

func TestCompact(t *testing.T) {
	input := []byte(`{
  "key": "value",
  "count": 42
}`)
	got, err := Compact(input)
	if err != nil {
		t.Fatalf("Compact() error: %v", err)
	}
	if strings.Contains(string(got), "\n") {
		t.Error("Compact should remove whitespace")
	}
	if !strings.Contains(string(got), "key") {
		t.Error("Compact should preserve data")
	}
}

func TestCompact_InvalidJSON(t *testing.T) {
	_, err := Compact([]byte("not json"))
	if err == nil {
		t.Error("Compact should error for invalid JSON")
	}
}

// ============================================================================
// Valid / ValidString
// ============================================================================

func TestValid(t *testing.T) {
	if !Valid([]byte(`{"key":"value"}`)) {
		t.Error("Valid should return true for valid JSON")
	}
	if Valid([]byte("not json")) {
		t.Error("Valid should return false for invalid JSON")
	}
}

func TestValidString(t *testing.T) {
	if !ValidString(`{"key":"value"}`) {
		t.Error("ValidString should return true for valid JSON")
	}
	if ValidString("not json") {
		t.Error("ValidString should return false for invalid JSON")
	}
}

// ============================================================================
// Merge
// ============================================================================

func TestMerge(t *testing.T) {
	a := map[string]interface{}{"key1": "a", "key2": "b"}
	b := map[string]interface{}{"key2": "B", "key3": "c"}
	result := Merge(a, b)

	if result["key1"] != "a" {
		t.Errorf("result[key1] = %v, want 'a'", result["key1"])
	}
	if result["key2"] != "B" {
		t.Errorf("result[key2] = %v, want 'B' (overwritten)", result["key2"])
	}
	if result["key3"] != "c" {
		t.Errorf("result[key3] = %v, want 'c'", result["key3"])
	}
}

func TestMerge_Empty(t *testing.T) {
	result := Merge()
	if len(result) != 0 {
		t.Error("Merge with no args should return empty map")
	}
}

// ============================================================================
// GetString / GetInt / GetBool / GetSlice / GetMap
// ============================================================================

func TestGetString(t *testing.T) {
	obj := map[string]interface{}{"name": "test", "count": 42}
	if got := GetString(obj, "name"); got != "test" {
		t.Errorf("GetString(name) = %q, want 'test'", got)
	}
	if got := GetString(obj, "missing"); got != "" {
		t.Errorf("GetString(missing) = %q, want empty", got)
	}
	if got := GetString(obj, "count"); got != "" {
		t.Errorf("GetString(count) = %q, want empty (not a string)", got)
	}
}

func TestGetInt(t *testing.T) {
	obj := map[string]interface{}{
		"int":     42,
		"int64":   int64(100),
		"float64": float64(99.9),
		"name":    "test",
	}

	if got := GetInt(obj, "int"); got != 42 {
		t.Errorf("GetInt(int) = %d, want 42", got)
	}
	if got := GetInt(obj, "int64"); got != 100 {
		t.Errorf("GetInt(int64) = %d, want 100", got)
	}
	if got := GetInt(obj, "float64"); got != 99 {
		t.Errorf("GetInt(float64) = %d, want 99", got)
	}
	if got := GetInt(obj, "missing"); got != 0 {
		t.Errorf("GetInt(missing) = %d, want 0", got)
	}
	if got := GetInt(obj, "name"); got != 0 {
		t.Errorf("GetInt(name) = %d, want 0 (not a number)", got)
	}
}

func TestGetBool(t *testing.T) {
	obj := map[string]interface{}{"active": true, "name": "test"}

	if got := GetBool(obj, "active"); !got {
		t.Error("GetBool(active) should be true")
	}
	if got := GetBool(obj, "missing"); got {
		t.Error("GetBool(missing) should be false")
	}
	if got := GetBool(obj, "name"); got {
		t.Error("GetBool(name) should be false (not a bool)")
	}
}

func TestGetSlice(t *testing.T) {
	obj := map[string]interface{}{
		"items": []interface{}{1, 2, 3},
		"name":  "test",
	}

	got := GetSlice(obj, "items")
	if len(got) != 3 {
		t.Errorf("GetSlice(items) length = %d, want 3", len(got))
	}
	if got := GetSlice(obj, "missing"); got != nil {
		t.Error("GetSlice(missing) should be nil")
	}
}

func TestGetMap(t *testing.T) {
	obj := map[string]interface{}{
		"nested": map[string]interface{}{"key": "value"},
		"name":   "test",
	}

	got := GetMap(obj, "nested")
	if got == nil {
		t.Fatal("GetMap(nested) should not be nil")
	}
	if got["key"] != "value" {
		t.Errorf("GetMap(nested)[key] = %v, want 'value'", got["key"])
	}
	if got := GetMap(obj, "missing"); got != nil {
		t.Error("GetMap(missing) should be nil")
	}
}

// ============================================================================
// ReadJSON / WriteJSON
// ============================================================================

func TestReadJSON(t *testing.T) {
	input := strings.NewReader(`{"name":"test","count":42}`)
	var result map[string]interface{}
	err := ReadJSON(input, &result)
	if err != nil {
		t.Fatalf("ReadJSON() error: %v", err)
	}
	if result["name"] != "test" {
		t.Errorf("result[name] = %v, want 'test'", result["name"])
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	err := WriteJSON(&buf, map[string]string{"key": "value"})
	if err != nil {
		t.Fatalf("WriteJSON() error: %v", err)
	}
	if !strings.Contains(buf.String(), "key") {
		t.Errorf("WriteJSON output = %q, expected to contain 'key'", buf.String())
	}
}

// ============================================================================
// ToMap / FromMap
// ============================================================================

func TestToMap(t *testing.T) {
	type input struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	v := input{Name: "test", Count: 5}
	m, err := ToMap(v)
	if err != nil {
		t.Fatalf("ToMap() error: %v", err)
	}
	if m["name"] != "test" {
		t.Errorf("ToMap()[name] = %v, want 'test'", m["name"])
	}
}

func TestFromMap(t *testing.T) {
	type output struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	m := map[string]interface{}{"name": "test", "count": float64(5)}
	var v output
	err := FromMap(m, &v)
	if err != nil {
		t.Fatalf("FromMap() error: %v", err)
	}
	if v.Name != "test" {
		t.Errorf("FromMap().Name = %q, want 'test'", v.Name)
	}
	if v.Count != 5 {
		t.Errorf("FromMap().Count = %d, want 5", v.Count)
	}
}

func TestToMapFromMap_RoundTrip(t *testing.T) {
	type data struct {
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	orig := data{Name: "round-trip", Enabled: true}

	m, err := ToMap(orig)
	if err != nil {
		t.Fatalf("ToMap() error: %v", err)
	}

	var result data
	if err := FromMap(m, &result); err != nil {
		t.Fatalf("FromMap() error: %v", err)
	}

	if result.Name != orig.Name || result.Enabled != orig.Enabled {
		t.Errorf("round-trip failed: got %+v, want %+v", result, orig)
	}
}
