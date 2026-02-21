// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package registry provides registry browsing capabilities — listing
// repositories, tags, and manifests from Docker-compatible v2 registries.
package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// RegistryStore provides access to stored registry credentials.
type RegistryStore interface {
	GetByID(ctx context.Context, id uuid.UUID) (*models.Registry, error)
	List(ctx context.Context) ([]*models.Registry, error)
	Create(ctx context.Context, input models.CreateRegistryInput) (*models.Registry, error)
	Update(ctx context.Context, id uuid.UUID, input models.CreateRegistryInput) (*models.Registry, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// Encryptor encrypts and decrypts stored registry passwords.
type Encryptor interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}

// Service provides registry browsing operations.
type Service struct {
	store     RegistryStore
	encryptor Encryptor
	client    *http.Client
	logger    *logger.Logger
}

// NewService creates a new registry browsing service.
func NewService(store RegistryStore, encryptor Encryptor, log *logger.Logger) *Service {
	return &Service{
		store:     store,
		encryptor: encryptor,
		client:    &http.Client{Timeout: 30 * time.Second},
		logger:    log.Named("registry"),
	}
}

// ============================================================================
// CRUD operations (delegate to store with encryption)
// ============================================================================

// ListRegistries returns all stored registries with passwords redacted.
func (s *Service) ListRegistries(ctx context.Context) ([]*models.Registry, error) {
	registries, err := s.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list registries: %w", err)
	}
	// Redact passwords in response
	for _, r := range registries {
		r.Password = nil
	}
	return registries, nil
}

// CreateRegistry creates a new registry, encrypting the password.
func (s *Service) CreateRegistry(ctx context.Context, name, url string, username, password *string, isDefault bool) (*models.Registry, error) {
	input := models.CreateRegistryInput{
		Name:      name,
		URL:       url,
		Username:  username,
		IsDefault: isDefault,
	}

	if password != nil && *password != "" && s.encryptor != nil {
		encrypted, err := s.encryptor.Encrypt(*password)
		if err != nil {
			return nil, fmt.Errorf("encrypt password: %w", err)
		}
		input.Password = &encrypted
	}

	reg, err := s.store.Create(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("create registry: %w", err)
	}

	reg.Password = nil
	return reg, nil
}

// UpdateRegistry updates a registry, encrypting the password if provided.
func (s *Service) UpdateRegistry(ctx context.Context, id uuid.UUID, name, url string, username, password *string, isDefault bool) (*models.Registry, error) {
	input := models.CreateRegistryInput{
		Name:      name,
		URL:       url,
		Username:  username,
		IsDefault: isDefault,
	}

	if password != nil && *password != "" && s.encryptor != nil {
		encrypted, err := s.encryptor.Encrypt(*password)
		if err != nil {
			return nil, fmt.Errorf("encrypt password: %w", err)
		}
		input.Password = &encrypted
	}

	reg, err := s.store.Update(ctx, id, input)
	if err != nil {
		return nil, fmt.Errorf("update registry: %w", err)
	}

	reg.Password = nil
	return reg, nil
}

// DeleteRegistry deletes a registry.
func (s *Service) DeleteRegistry(ctx context.Context, id uuid.UUID) error {
	return s.store.Delete(ctx, id)
}

// ListRepositories lists repositories in a registry. For Docker Hub, uses the
// Hub API which returns richer metadata. For generic v2 registries, uses the
// _catalog endpoint.
func (s *Service) ListRepositories(ctx context.Context, registryID uuid.UUID, namespace string, page, perPage int) ([]*models.RegistryRepoInfo, error) {
	reg, creds, err := s.resolveRegistry(ctx, registryID)
	if err != nil {
		return nil, err
	}

	host := extractHost(reg.URL)

	if isDockerHub(host) {
		return s.listDockerHubRepos(ctx, namespace, page, perPage)
	}

	return s.listV2Catalog(ctx, host, creds, perPage)
}

// ListTags lists tags for a repository in a registry.
func (s *Service) ListTags(ctx context.Context, registryID uuid.UUID, repository string) ([]*models.RegistryTagInfo, error) {
	reg, creds, err := s.resolveRegistry(ctx, registryID)
	if err != nil {
		return nil, err
	}

	host := extractHost(reg.URL)

	if isDockerHub(host) {
		return s.listDockerHubTags(ctx, repository)
	}

	return s.listV2Tags(ctx, host, repository, creds)
}

// GetManifest retrieves manifest details for a specific tag.
func (s *Service) GetManifest(ctx context.Context, registryID uuid.UUID, repository, reference string) (*models.RegistryManifestInfo, error) {
	reg, creds, err := s.resolveRegistry(ctx, registryID)
	if err != nil {
		return nil, err
	}

	host := extractHost(reg.URL)

	if isDockerHub(host) {
		return s.getDockerHubManifest(ctx, repository, reference)
	}

	return s.getV2Manifest(ctx, host, repository, reference, creds)
}

// resolveRegistry fetches the registry record and decrypts credentials.
func (s *Service) resolveRegistry(ctx context.Context, id uuid.UUID) (*models.Registry, *credentials, error) {
	reg, err := s.store.GetByID(ctx, id)
	if err != nil {
		return nil, nil, fmt.Errorf("registry not found: %w", err)
	}

	creds := &credentials{}
	if reg.Username != nil {
		creds.username = *reg.Username
	}
	if reg.Password != nil && *reg.Password != "" && s.encryptor != nil {
		decrypted, err := s.encryptor.Decrypt(*reg.Password)
		if err != nil {
			s.logger.Warn("failed to decrypt registry password", "registry_id", id, "error", err)
		} else {
			creds.password = decrypted
		}
	}

	return reg, creds, nil
}

type credentials struct {
	username string
	password string
}

// ============================================================================
// Docker Hub API
// ============================================================================

func (s *Service) listDockerHubRepos(ctx context.Context, namespace string, page, perPage int) ([]*models.RegistryRepoInfo, error) {
	if namespace == "" {
		namespace = "library"
	}
	if perPage <= 0 {
		perPage = 25
	}
	if perPage > 100 {
		perPage = 100
	}
	if page < 1 {
		page = 1
	}

	url := fmt.Sprintf("https://hub.docker.com/v2/repositories/%s/?page=%d&page_size=%d", namespace, page, perPage)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker hub request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker hub returned %d", resp.StatusCode)
	}

	var hubResp struct {
		Results []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			PullCount   int64  `json:"pull_count"`
			StarCount   int    `json:"star_count"`
			IsPrivate   bool   `json:"is_private"`
			LastUpdated string `json:"last_updated"`
		} `json:"results"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&hubResp); err != nil {
		return nil, fmt.Errorf("decode docker hub response: %w", err)
	}

	repos := make([]*models.RegistryRepoInfo, 0, len(hubResp.Results))
	for _, r := range hubResp.Results {
		info := &models.RegistryRepoInfo{
			Name:        r.Name,
			Description: r.Description,
			PullCount:   r.PullCount,
			StarCount:   r.StarCount,
			IsPrivate:   r.IsPrivate,
		}
		if r.LastUpdated != "" {
			if t, err := time.Parse(time.RFC3339Nano, r.LastUpdated); err == nil {
				info.LastUpdated = &t
			}
		}
		repos = append(repos, info)
	}

	return repos, nil
}

func (s *Service) listDockerHubTags(ctx context.Context, repository string) ([]*models.RegistryTagInfo, error) {
	// Normalize: "nginx" → "library/nginx"
	if !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}

	token, err := s.getDockerHubToken(ctx, repository)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("https://registry-1.docker.io/v2/%s/tags/list", repository)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("docker hub tags request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker hub tags returned %d", resp.StatusCode)
	}

	var tagsResp struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&tagsResp); err != nil {
		return nil, fmt.Errorf("decode tags response: %w", err)
	}

	tags := make([]*models.RegistryTagInfo, 0, len(tagsResp.Tags))
	for _, t := range tagsResp.Tags {
		tags = append(tags, &models.RegistryTagInfo{Name: t})
	}

	return tags, nil
}

func (s *Service) getDockerHubManifest(ctx context.Context, repository, reference string) (*models.RegistryManifestInfo, error) {
	if !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}

	token, err := s.getDockerHubToken(ctx, repository)
	if err != nil {
		return nil, err
	}

	return s.fetchManifest(ctx, "registry-1.docker.io", repository, reference, token)
}

func (s *Service) getDockerHubToken(ctx context.Context, repository string) (string, error) {
	url := fmt.Sprintf("https://auth.docker.io/token?service=registry.docker.io&scope=repository:%s:pull", repository)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create token request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode token response: %w", err)
	}

	return tokenResp.Token, nil
}

// ============================================================================
// Generic OCI / Docker Registry V2 API
// ============================================================================

func (s *Service) listV2Catalog(ctx context.Context, host string, creds *credentials, limit int) ([]*models.RegistryRepoInfo, error) {
	if limit <= 0 {
		limit = 100
	}

	url := fmt.Sprintf("https://%s/v2/_catalog?n=%d", host, limit)
	token := s.getV2Token(ctx, host, "", creds)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create catalog request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if creds.username != "" {
		req.SetBasicAuth(creds.username, creds.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("catalog request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("registry authentication failed (401)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("catalog returned %d", resp.StatusCode)
	}

	var catalogResp struct {
		Repositories []string `json:"repositories"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&catalogResp); err != nil {
		return nil, fmt.Errorf("decode catalog response: %w", err)
	}

	repos := make([]*models.RegistryRepoInfo, 0, len(catalogResp.Repositories))
	for _, name := range catalogResp.Repositories {
		repos = append(repos, &models.RegistryRepoInfo{Name: name})
	}

	return repos, nil
}

func (s *Service) listV2Tags(ctx context.Context, host, repository string, creds *credentials) ([]*models.RegistryTagInfo, error) {
	url := fmt.Sprintf("https://%s/v2/%s/tags/list", host, repository)
	token := s.getV2Token(ctx, host, repository, creds)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create tags request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else if creds.username != "" {
		req.SetBasicAuth(creds.username, creds.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("tags request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("registry authentication failed (401)")
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("repository %q not found", repository)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tags returned %d", resp.StatusCode)
	}

	var tagsResp struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 2*1024*1024)).Decode(&tagsResp); err != nil {
		return nil, fmt.Errorf("decode tags response: %w", err)
	}

	tags := make([]*models.RegistryTagInfo, 0, len(tagsResp.Tags))
	for _, t := range tagsResp.Tags {
		tags = append(tags, &models.RegistryTagInfo{Name: t})
	}

	return tags, nil
}

func (s *Service) getV2Manifest(ctx context.Context, host, repository, reference string, creds *credentials) (*models.RegistryManifestInfo, error) {
	token := s.getV2Token(ctx, host, repository, creds)
	return s.fetchManifest(ctx, host, repository, reference, token)
}

// fetchManifest performs a HEAD + GET on the manifest endpoint.
func (s *Service) fetchManifest(ctx context.Context, host, repository, reference, token string) (*models.RegistryManifestInfo, error) {
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", host, repository, reference)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create manifest request: %w", err)
	}
	req.Header.Set("Accept", strings.Join([]string{
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.docker.distribution.manifest.v2+json",
		"application/vnd.docker.distribution.manifest.list.v2+json",
	}, ", "))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("manifest request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("manifest %q not found in %s", reference, repository)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest returned %d", resp.StatusCode)
	}

	digest := resp.Header.Get("Docker-Content-Digest")
	mediaType := resp.Header.Get("Content-Type")

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read manifest body: %w", err)
	}

	info := &models.RegistryManifestInfo{
		Digest:    digest,
		MediaType: mediaType,
		Size:      int64(len(body)),
	}

	// Parse layers from the manifest JSON.
	var manifest struct {
		Layers []struct {
			Size int64 `json:"size"`
		} `json:"layers"`
		Config struct {
			MediaType string `json:"mediaType"`
		} `json:"config"`
	}
	if json.Unmarshal(body, &manifest) == nil && len(manifest.Layers) > 0 {
		info.Layers = len(manifest.Layers)
		var totalSize int64
		for _, l := range manifest.Layers {
			totalSize += l.Size
		}
		info.Size = totalSize
	}

	return info, nil
}

// getV2Token attempts a token exchange via the Www-Authenticate challenge.
// If no challenge is needed (private registries with basic auth), returns "".
func (s *Service) getV2Token(ctx context.Context, host, repository string, creds *credentials) string {
	// Probe the v2 API to check if token auth is needed.
	checkURL := fmt.Sprintf("https://%s/v2/", host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checkURL, nil)
	if err != nil {
		return ""
	}
	if creds.username != "" {
		req.SetBasicAuth(creds.username, creds.password)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		return ""
	}

	// Parse Www-Authenticate: Bearer realm="...",service="...",scope="..."
	challenge := resp.Header.Get("Www-Authenticate")
	if challenge == "" {
		return ""
	}

	params := parseWWWAuthenticate(challenge)
	realm := params["realm"]
	if realm == "" {
		return ""
	}

	service := params["service"]
	scope := params["scope"]
	if scope == "" && repository != "" {
		scope = fmt.Sprintf("repository:%s:pull", repository)
	}

	tokenURL := realm
	sep := "?"
	if strings.Contains(tokenURL, "?") {
		sep = "&"
	}
	if service != "" {
		tokenURL += sep + "service=" + service
		sep = "&"
	}
	if scope != "" {
		tokenURL += sep + "scope=" + scope
	}

	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return ""
	}
	if creds.username != "" {
		tokenReq.SetBasicAuth(creds.username, creds.password)
	}

	tokenResp, err := s.client.Do(tokenReq)
	if err != nil {
		return ""
	}
	defer tokenResp.Body.Close()

	var tokenBody struct {
		Token       string `json:"token"`
		AccessToken string `json:"access_token"`
	}
	if json.NewDecoder(io.LimitReader(tokenResp.Body, 64*1024)).Decode(&tokenBody) != nil {
		return ""
	}

	if tokenBody.Token != "" {
		return tokenBody.Token
	}
	return tokenBody.AccessToken
}

// ============================================================================
// Helpers
// ============================================================================

func extractHost(registryURL string) string {
	u := registryURL
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimSuffix(u, "/")
	if idx := strings.Index(u, "/"); idx > 0 {
		u = u[:idx]
	}
	return u
}

func isDockerHub(host string) bool {
	switch strings.ToLower(host) {
	case "docker.io", "index.docker.io", "registry-1.docker.io", "registry.hub.docker.com", "hub.docker.com":
		return true
	}
	return false
}

// parseWWWAuthenticate parses a Bearer challenge header into key=value pairs.
func parseWWWAuthenticate(header string) map[string]string {
	params := make(map[string]string)
	header = strings.TrimPrefix(header, "Bearer ")
	header = strings.TrimPrefix(header, "bearer ")

	for _, part := range splitChallenge(header) {
		part = strings.TrimSpace(part)
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		val := strings.TrimSpace(part[eq+1:])
		val = strings.Trim(val, `"`)
		params[key] = val
	}

	return params
}

// splitChallenge splits on commas that are not inside quoted strings.
func splitChallenge(s string) []string {
	var parts []string
	var current strings.Builder
	inQuotes := false

	for _, c := range s {
		switch {
		case c == '"':
			inQuotes = !inQuotes
			current.WriteRune(c)
		case c == ',' && !inQuotes:
			parts = append(parts, current.String())
			current.Reset()
		default:
			current.WriteRune(c)
		}
	}

	if current.Len() > 0 {
		parts = append(parts, current.String())
	}

	return parts
}
