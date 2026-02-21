// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ReceiptStore struct {
	path string
}

func NewReceiptStore(dataDir string) *ReceiptStore {
	return &ReceiptStore{
		path: filepath.Join(dataDir, "activation_receipt.jwt"),
	}
}

func (s *ReceiptStore) Save(jwt string) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return fmt.Errorf("receipt store: mkdir: %w", err)
	}
	if err := os.WriteFile(s.path, []byte(jwt+"\n"), 0600); err != nil {
		return fmt.Errorf("receipt store: write: %w", err)
	}
	return nil
}

func (s *ReceiptStore) Load() (string, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("receipt store: read: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

func (s *ReceiptStore) Remove() error {
	err := os.Remove(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("receipt store: remove: %w", err)
	}
	return nil
}

func (s *ReceiptStore) Path() string {
	return s.path
}
