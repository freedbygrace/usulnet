// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"encoding/hex"
	"errors"
	"testing"
)

// ============================================================================
// NewAESEncryptor
// ============================================================================

func TestNewAESEncryptor(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}

	enc, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("NewAESEncryptor() error: %v", err)
	}
	if enc == nil {
		t.Fatal("NewAESEncryptor() returned nil")
	}
}

func TestNewAESEncryptor_InvalidHex(t *testing.T) {
	_, err := NewAESEncryptor("not-valid-hex")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

func TestNewAESEncryptor_WrongLength(t *testing.T) {
	// 16 bytes (AES-128, not AES-256)
	shortKey := hex.EncodeToString(make([]byte, 16))
	_, err := NewAESEncryptor(shortKey)
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for wrong length, got: %v", err)
	}
}

func TestNewAESEncryptorFromBytes(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := NewAESEncryptorFromBytes(key)
	if err != nil {
		t.Fatalf("NewAESEncryptorFromBytes() error: %v", err)
	}
	if enc == nil {
		t.Fatal("NewAESEncryptorFromBytes() returned nil")
	}
}

func TestNewAESEncryptorFromBytes_WrongLength(t *testing.T) {
	_, err := NewAESEncryptorFromBytes(make([]byte, 16))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

func TestNewEncryptor_BackwardCompatibility(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatalf("NewEncryptor() error: %v", err)
	}
	if enc == nil {
		t.Fatal("NewEncryptor() returned nil")
	}
}

// ============================================================================
// Encrypt / Decrypt (base64)
// ============================================================================

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	enc, err := NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("NewAESEncryptor() error: %v", err)
	}

	plaintext := []byte("hello, world! This is sensitive data.")
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	if string(plaintext) == ciphertext {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := enc.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %q, want %q", decrypted, plaintext)
	}
}

func TestEncrypt_DifferentCiphertextEachTime(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)
	plaintext := []byte("same input")

	c1, _ := enc.Encrypt(plaintext)
	c2, _ := enc.Encrypt(plaintext)

	if c1 == c2 {
		t.Error("Encrypt should produce different ciphertext each time (random nonce)")
	}
}

func TestDecrypt_InvalidBase64(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)

	_, err := enc.Decrypt("not-valid-base64!!!")
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got: %v", err)
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)

	// Base64 of just a few bytes (shorter than nonce)
	_, err := enc.Decrypt("AQID")
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext for too short, got: %v", err)
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	enc1, _ := NewAESEncryptor(key1)
	enc2, _ := NewAESEncryptor(key2)

	ciphertext, _ := enc1.Encrypt([]byte("secret"))
	_, err := enc2.Decrypt(ciphertext)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed for wrong key, got: %v", err)
	}
}

// ============================================================================
// EncryptString / DecryptString
// ============================================================================

func TestEncryptDecryptString_RoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)

	plaintext := "sensitive string data"
	ciphertext, err := enc.EncryptString(plaintext)
	if err != nil {
		t.Fatalf("EncryptString() error: %v", err)
	}

	decrypted, err := enc.DecryptString(ciphertext)
	if err != nil {
		t.Fatalf("DecryptString() error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("DecryptString() = %q, want %q", decrypted, plaintext)
	}
}

// ============================================================================
// EncryptToHex / DecryptFromHex
// ============================================================================

func TestEncryptDecryptHex_RoundTrip(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)

	plaintext := []byte("hex encryption test")
	cipherHex, err := enc.EncryptToHex(plaintext)
	if err != nil {
		t.Fatalf("EncryptToHex() error: %v", err)
	}

	// Should be valid hex
	if _, err := hex.DecodeString(cipherHex); err != nil {
		t.Errorf("EncryptToHex output is not valid hex: %v", err)
	}

	decrypted, err := enc.DecryptFromHex(cipherHex)
	if err != nil {
		t.Fatalf("DecryptFromHex() error: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("DecryptFromHex() = %q, want %q", decrypted, plaintext)
	}
}

func TestDecryptFromHex_InvalidHex(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)

	_, err := enc.DecryptFromHex("not-hex!")
	if !errors.Is(err, ErrInvalidCiphertext) {
		t.Errorf("expected ErrInvalidCiphertext, got: %v", err)
	}
}

func TestDecryptFromHex_WrongKey(t *testing.T) {
	key1, _ := GenerateKey()
	key2, _ := GenerateKey()
	enc1, _ := NewAESEncryptor(key1)
	enc2, _ := NewAESEncryptor(key2)

	cipherHex, _ := enc1.EncryptToHex([]byte("secret"))
	_, err := enc2.DecryptFromHex(cipherHex)
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed for wrong key, got: %v", err)
	}
}

// ============================================================================
// GenerateKey / ValidateKey
// ============================================================================

func TestGenerateKey(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error: %v", err)
	}
	// 32 bytes = 64 hex chars
	if len(key) != 64 {
		t.Errorf("GenerateKey() length = %d, want 64", len(key))
	}
}

func TestGenerateKey_Unique(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	if k1 == k2 {
		t.Error("GenerateKey() should produce unique keys")
	}
}

func TestValidateKey_Valid(t *testing.T) {
	key, _ := GenerateKey()
	if err := ValidateKey(key); err != nil {
		t.Errorf("ValidateKey() should pass for valid key: %v", err)
	}
}

func TestValidateKey_InvalidHex(t *testing.T) {
	err := ValidateKey("not-hex")
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey, got: %v", err)
	}
}

func TestValidateKey_WrongLength(t *testing.T) {
	err := ValidateKey(hex.EncodeToString(make([]byte, 16)))
	if !errors.Is(err, ErrInvalidKey) {
		t.Errorf("expected ErrInvalidKey for wrong length, got: %v", err)
	}
}

// ============================================================================
// Encrypt empty data
// ============================================================================

func TestEncryptDecrypt_EmptyData(t *testing.T) {
	key, _ := GenerateKey()
	enc, _ := NewAESEncryptor(key)

	ct, err := enc.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt(empty) error: %v", err)
	}

	pt, err := enc.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt(empty) error: %v", err)
	}
	if len(pt) != 0 {
		t.Errorf("Decrypt(empty) = %v, want empty", pt)
	}
}
