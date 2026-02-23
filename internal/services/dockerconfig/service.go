// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dockerconfig

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Service manages Docker daemon configuration (daemon.json).
type Service struct {
	logger      *logger.Logger
	configPath  string
	backupDir   string
	mu          sync.Mutex
	containerID string // non-empty when running in a Docker container with host PID ns
}

// NewService creates a new Docker config service.
func NewService(cfg Config, log *logger.Logger) *Service {
	configPath := cfg.ConfigPath
	if configPath == "" {
		configPath = "/etc/docker/daemon.json"
	}
	backupDir := cfg.BackupDir
	if backupDir == "" {
		backupDir = "/etc/docker/backups"
	}
	s := &Service{
		logger:     log.Named("dockerconfig"),
		configPath: configPath,
		backupDir:  backupDir,
	}

	// Detect if running in a Docker container with host PID namespace.
	// In this setup, /etc/docker/daemon.json lives on the host, not in the
	// container. We use nsenter via docker exec to access host files.
	if id := detectContainerID(); id != "" && isHostPIDNS() {
		s.containerID = id
		s.logger.Info("Running in container with host PID ns, using nsenter for host file access",
			"container_id", id)
	}

	return s
}

// Read reads and parses the current daemon.json file.
// Returns an empty DaemonConfig if the file does not exist (valid Docker state).
func (s *Service) Read(_ context.Context) (*DaemonConfig, error) {
	data, err := s.readConfigFile()
	if err != nil {
		if os.IsNotExist(err) {
			return &DaemonConfig{}, nil
		}
		return nil, fmt.Errorf("read daemon.json: %w", err)
	}
	if len(data) == 0 {
		return &DaemonConfig{}, nil
	}

	var cfg DaemonConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse daemon.json: %w", err)
	}
	return &cfg, nil
}

// ReadRaw returns the raw daemon.json content as a pretty-printed string.
func (s *Service) ReadRaw(_ context.Context) (string, error) {
	data, err := s.readConfigFile()
	if err != nil {
		if os.IsNotExist(err) {
			return "{}", nil
		}
		return "", fmt.Errorf("read daemon.json: %w", err)
	}
	if len(data) == 0 {
		return "{}", nil
	}
	// Re-format with indentation
	var raw json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return string(data), nil // return as-is if not valid JSON
	}
	pretty, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return string(data), nil
	}
	return string(pretty), nil
}

// UpdateCategory applies changes from a specific settings category.
// Flow: read → merge → validate → backup → write → return apply mode.
func (s *Service) UpdateCategory(ctx context.Context, category string, changes map[string]interface{}) (*UpdateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Read current config
	current, err := s.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("read current config: %w", err)
	}

	// 2. Merge changes
	changedFields := mergeCategory(current, category, changes)

	// 3. Validate merged config
	if errs := ValidateConfig(current); len(errs) > 0 {
		return nil, fmt.Errorf("validation failed: %s", FormatValidationErrors(errs))
	}

	// 4. Backup current daemon.json (only if file exists)
	var backupPath string
	if s.configFileExists() {
		backupPath, err = s.backup()
		if err != nil {
			return nil, fmt.Errorf("backup before write: %w", err)
		}
	}

	// 5. Write new daemon.json
	data, err := json.MarshalIndent(current, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	data = append(data, '\n')

	if err := s.writeConfigFile(data); err != nil {
		return nil, fmt.Errorf("write daemon.json: %w", err)
	}

	// 6. Determine apply mode
	applyMode := determineApplyMode(changedFields)

	s.logger.Info("Docker daemon config updated",
		"category", category,
		"backup", backupPath,
		"apply_mode", string(applyMode),
		"changed_fields", strings.Join(changedFields, ", "),
	)

	return &UpdateResult{
		BackupPath:    backupPath,
		ApplyMode:     applyMode,
		ChangedFields: changedFields,
	}, nil
}

// Backup creates a timestamped backup of daemon.json.
func (s *Service) Backup(_ context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.backup()
}

func (s *Service) backup() (string, error) {
	if err := os.MkdirAll(s.backupDir, 0o755); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}

	data, err := s.readConfigFile()
	if err != nil {
		return "", fmt.Errorf("read daemon.json for backup: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	backupPath := filepath.Join(s.backupDir, fmt.Sprintf("daemon.json.%s.bak", timestamp))

	if err := os.WriteFile(backupPath, data, 0o644); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}

	s.logger.Info("Daemon.json backup created", "path", backupPath)
	return backupPath, nil
}

// ListBackups returns available daemon.json backups, newest first.
func (s *Service) ListBackups(_ context.Context) ([]BackupInfo, error) {
	entries, err := os.ReadDir(s.backupDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read backup directory: %w", err)
	}

	var backups []BackupInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "daemon.json.") || !strings.HasSuffix(e.Name(), ".bak") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, BackupInfo{
			Name:      e.Name(),
			Path:      filepath.Join(s.backupDir, e.Name()),
			Size:      info.Size(),
			Timestamp: info.ModTime(),
		})
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].Timestamp.After(backups[j].Timestamp)
	})

	return backups, nil
}

// RestoreBackup restores a specific backup file after backing up the current config.
func (s *Service) RestoreBackup(ctx context.Context, backupName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Sanitize name to prevent path traversal
	cleanName := filepath.Base(backupName)
	if cleanName != backupName || strings.Contains(cleanName, "..") {
		return fmt.Errorf("invalid backup name")
	}

	backupPath := filepath.Join(s.backupDir, cleanName)

	// Read backup file
	data, err := os.ReadFile(backupPath)
	if err != nil {
		return fmt.Errorf("read backup file: %w", err)
	}

	// Validate it's valid JSON
	var test json.RawMessage
	if err := json.Unmarshal(data, &test); err != nil {
		return fmt.Errorf("backup file is not valid JSON: %w", err)
	}

	// Backup current config before restoring
	if s.configFileExists() {
		if _, err := s.backup(); err != nil {
			return fmt.Errorf("pre-restore backup: %w", err)
		}
	}

	// Write restored config
	if err := s.writeConfigFile(data); err != nil {
		return fmt.Errorf("write restored config: %w", err)
	}

	s.logger.Info("Daemon.json restored from backup", "backup", cleanName)
	return nil
}

// ReloadDaemon sends SIGHUP to the Docker daemon for live-reloadable settings.
func (s *Service) ReloadDaemon(ctx context.Context) error {
	out, err := exec.CommandContext(ctx, "pidof", "dockerd").Output()
	if err != nil {
		return fmt.Errorf("cannot find dockerd process: %w", err)
	}
	pidStr := strings.TrimSpace(string(out))
	fields := strings.Fields(pidStr)
	if len(fields) == 0 {
		return fmt.Errorf("dockerd not running")
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil {
		return fmt.Errorf("invalid dockerd PID %q: %w", fields[0], err)
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("send SIGHUP to dockerd (PID %d): %w", pid, err)
	}
	s.logger.Info("Docker daemon reloaded via SIGHUP", "pid", pid)
	return nil
}

// RestartDaemon restarts the Docker daemon via systemctl.
func (s *Service) RestartDaemon(ctx context.Context) error {
	s.logger.Warn("Restarting Docker daemon via systemctl")
	cmd := exec.CommandContext(ctx, "systemctl", "restart", "docker")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart docker: %s (%w)", strings.TrimSpace(string(out)), err)
	}
	s.logger.Info("Docker daemon restarted successfully")
	return nil
}

// mergeCategory applies form changes into the DaemonConfig for a specific category.
// Returns the list of field keys that were changed.
func mergeCategory(cfg *DaemonConfig, category string, changes map[string]interface{}) []string {
	var changed []string

	switch category {
	case "network":
		changed = mergeNetwork(cfg, changes)
	case "logging":
		changed = mergeLogging(cfg, changes)
	case "registry":
		changed = mergeRegistry(cfg, changes)
	case "runtime":
		changed = mergeRuntime(cfg, changes)
	case "proxy":
		changed = mergeProxy(cfg, changes)
	case "security":
		changed = mergeSecurity(cfg, changes)
	case "general":
		changed = mergeGeneral(cfg, changes)
	}

	return changed
}

func mergeNetwork(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	if v := getString(c, "bip"); v != nil {
		cfg.BIP = nilIfEmpty(v)
		changed = append(changed, "bip")
	}
	if v := getString(c, "fixed_cidr"); v != nil {
		cfg.FixedCIDR = nilIfEmpty(v)
		changed = append(changed, "fixed-cidr")
	}
	if v := getString(c, "default_gateway"); v != nil {
		cfg.DefaultGateway = nilIfEmpty(v)
		changed = append(changed, "default-gateway")
	}
	if v, ok := c["dns"]; ok {
		cfg.DNS = toStringSlice(v)
		changed = append(changed, "dns")
	}
	if v, ok := c["dns_search"]; ok {
		cfg.DNSSearch = toStringSlice(v)
		changed = append(changed, "dns-search")
	}
	if v, ok := c["dns_opts"]; ok {
		cfg.DNSOpts = toStringSlice(v)
		changed = append(changed, "dns-opts")
	}
	if v := getInt(c, "mtu"); v != nil {
		if *v == 0 {
			cfg.MTU = nil
		} else {
			cfg.MTU = v
		}
		changed = append(changed, "mtu")
	}
	if v := getBool(c, "icc"); v != nil {
		cfg.ICC = v
		changed = append(changed, "icc")
	}
	if v := getBool(c, "ipv6"); v != nil {
		cfg.IPv6 = v
		changed = append(changed, "ipv6")
	}
	if v := getBool(c, "ip_forward"); v != nil {
		cfg.IPForward = v
		changed = append(changed, "ip-forward")
	}
	if v := getBool(c, "ip_masq"); v != nil {
		cfg.IPMasq = v
		changed = append(changed, "ip-masq")
	}
	if v, ok := c["default_address_pools"]; ok {
		if pools, ok := v.([]AddressPool); ok {
			if len(pools) == 0 {
				cfg.DefaultAddressPools = nil
			} else {
				cfg.DefaultAddressPools = pools
			}
			changed = append(changed, "default-address-pools")
		}
	}
	return changed
}

func mergeLogging(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	if v := getString(c, "log_driver"); v != nil {
		cfg.LogDriver = nilIfEmpty(v)
		changed = append(changed, "log-driver")
	}
	if v := getString(c, "log_level"); v != nil {
		cfg.LogLevel = nilIfEmpty(v)
		changed = append(changed, "log-level")
	}
	if v := getString(c, "log_format"); v != nil {
		cfg.LogFormat = nilIfEmpty(v)
		changed = append(changed, "log-format")
	}
	if v, ok := c["log_opts"]; ok {
		if opts, ok := v.(map[string]string); ok {
			// Remove empty values
			cleaned := make(map[string]string)
			for k, val := range opts {
				if val != "" {
					cleaned[k] = val
				}
			}
			if len(cleaned) == 0 {
				cfg.LogOpts = nil
			} else {
				cfg.LogOpts = cleaned
			}
			changed = append(changed, "log-opts")
		}
	}
	return changed
}

func mergeRegistry(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	if v, ok := c["registry_mirrors"]; ok {
		cfg.RegistryMirrors = toStringSlice(v)
		changed = append(changed, "registry-mirrors")
	}
	if v, ok := c["insecure_registries"]; ok {
		cfg.InsecureRegistries = toStringSlice(v)
		changed = append(changed, "insecure-registries")
	}
	if v, ok := c["allow_nondistributable_artifacts"]; ok {
		cfg.AllowNondistributableArtifacts = toStringSlice(v)
		changed = append(changed, "allow-nondistributable-artifacts")
	}
	return changed
}

func mergeRuntime(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	if v := getString(c, "default_runtime"); v != nil {
		cfg.DefaultRuntime = nilIfEmpty(v)
		changed = append(changed, "default-runtime")
	}
	if v := getBool(c, "live_restore"); v != nil {
		cfg.LiveRestore = v
		changed = append(changed, "live-restore")
	}
	if v := getBool(c, "userland_proxy"); v != nil {
		cfg.UserlandProxy = v
		changed = append(changed, "userland-proxy")
	}
	if v := getBool(c, "iptables"); v != nil {
		cfg.Iptables = v
		changed = append(changed, "iptables")
	}
	if v := getBool(c, "ip6tables"); v != nil {
		cfg.IP6Tables = v
		changed = append(changed, "ip6tables")
	}
	if v := getBool(c, "init"); v != nil {
		cfg.Init = v
		changed = append(changed, "init")
	}
	if v, ok := c["exec_opts"]; ok {
		cfg.ExecOpts = toStringSlice(v)
		changed = append(changed, "exec-opts")
	}
	if v := getString(c, "default_cgroupns_mode"); v != nil {
		cfg.DefaultCgroupnsMode = nilIfEmpty(v)
		changed = append(changed, "default-cgroupns-mode")
	}
	if v := getString(c, "storage_driver"); v != nil {
		cfg.StorageDriver = nilIfEmpty(v)
		changed = append(changed, "storage-driver")
	}
	if v, ok := c["storage_opts"]; ok {
		cfg.StorageOpts = toStringSlice(v)
		changed = append(changed, "storage-opts")
	}
	if v := getString(c, "data_root"); v != nil {
		cfg.DataRoot = nilIfEmpty(v)
		changed = append(changed, "data-root")
	}
	if v, ok := c["runtimes"]; ok {
		if runtimes, ok := v.(map[string]Runtime); ok {
			if len(runtimes) == 0 {
				cfg.Runtimes = nil
			} else {
				cfg.Runtimes = runtimes
			}
			changed = append(changed, "runtimes")
		}
	}
	return changed
}

func mergeProxy(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	httpProxy := getString(c, "http_proxy")
	httpsProxy := getString(c, "https_proxy")
	noProxy := getString(c, "no_proxy")

	if httpProxy != nil || httpsProxy != nil || noProxy != nil {
		if cfg.Proxies == nil {
			cfg.Proxies = &ProxyConfig{}
		}
		if httpProxy != nil {
			cfg.Proxies.HTTPProxy = nilIfEmpty(httpProxy)
			changed = append(changed, "proxies.http-proxy")
		}
		if httpsProxy != nil {
			cfg.Proxies.HTTPSProxy = nilIfEmpty(httpsProxy)
			changed = append(changed, "proxies.https-proxy")
		}
		if noProxy != nil {
			cfg.Proxies.NoProxy = nilIfEmpty(noProxy)
			changed = append(changed, "proxies.no-proxy")
		}
		// Remove proxies if all empty
		if cfg.Proxies.HTTPProxy == nil && cfg.Proxies.HTTPSProxy == nil && cfg.Proxies.NoProxy == nil {
			cfg.Proxies = nil
		}
	}
	return changed
}

func mergeSecurity(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	if v := getBool(c, "no_new_privileges"); v != nil {
		cfg.NoNewPrivileges = v
		changed = append(changed, "no-new-privileges")
	}
	if v := getString(c, "seccomp_profile"); v != nil {
		cfg.SeccompProfile = nilIfEmpty(v)
		changed = append(changed, "seccomp-profile")
	}
	if v := getBool(c, "selinux_enabled"); v != nil {
		cfg.SELinuxEnabled = v
		changed = append(changed, "selinux-enabled")
	}
	if v := getString(c, "userns_remap"); v != nil {
		cfg.UsernsRemap = nilIfEmpty(v)
		changed = append(changed, "userns-remap")
	}
	if v, ok := c["authorization_plugins"]; ok {
		cfg.AuthorizationPlugins = toStringSlice(v)
		changed = append(changed, "authorization-plugins")
	}
	if v, ok := c["default_ulimits"]; ok {
		if ulimits, ok := v.(map[string]Ulimit); ok {
			if len(ulimits) == 0 {
				cfg.DefaultUlimits = nil
			} else {
				cfg.DefaultUlimits = ulimits
			}
			changed = append(changed, "default-ulimits")
		}
	}
	return changed
}

func mergeGeneral(cfg *DaemonConfig, c map[string]interface{}) []string {
	var changed []string
	if v := getBool(c, "debug"); v != nil {
		cfg.Debug = v
		changed = append(changed, "debug")
	}
	if v, ok := c["labels"]; ok {
		cfg.Labels = toStringSlice(v)
		changed = append(changed, "labels")
	}
	if v := getInt(c, "shutdown_timeout"); v != nil {
		if *v == 0 {
			cfg.ShutdownTimeout = nil
		} else {
			cfg.ShutdownTimeout = v
		}
		changed = append(changed, "shutdown-timeout")
	}
	if v := getInt(c, "max_concurrent_downloads"); v != nil {
		if *v == 0 {
			cfg.MaxConcurrentDownloads = nil
		} else {
			cfg.MaxConcurrentDownloads = v
		}
		changed = append(changed, "max-concurrent-downloads")
	}
	if v := getInt(c, "max_concurrent_uploads"); v != nil {
		if *v == 0 {
			cfg.MaxConcurrentUploads = nil
		} else {
			cfg.MaxConcurrentUploads = v
		}
		changed = append(changed, "max-concurrent-uploads")
	}
	if v := getInt(c, "max_download_attempts"); v != nil {
		if *v == 0 {
			cfg.MaxDownloadAttempts = nil
		} else {
			cfg.MaxDownloadAttempts = v
		}
		changed = append(changed, "max-download-attempts")
	}
	if v := getBool(c, "experimental"); v != nil {
		cfg.Experimental = v
		changed = append(changed, "experimental")
	}
	if v := getString(c, "metrics_addr"); v != nil {
		cfg.MetricsAddr = nilIfEmpty(v)
		changed = append(changed, "metrics-addr")
	}
	return changed
}

// determineApplyMode returns the "worst-case" apply mode for the changed fields.
func determineApplyMode(changedFields []string) ApplyMode {
	meta := AllSettingsMeta()
	for _, field := range changedFields {
		if m, ok := meta[field]; ok && m.ApplyMode == ApplyRestart {
			return ApplyRestart
		}
	}
	return ApplyReload
}

// Helpers for extracting typed values from map[string]interface{}
func getString(m map[string]interface{}, key string) *string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func getBool(m map[string]interface{}, key string) *bool {
	v, ok := m[key]
	if !ok {
		return nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil
	}
	return &b
}

func getInt(m map[string]interface{}, key string) *int {
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch n := v.(type) {
	case int:
		return &n
	case float64:
		i := int(n)
		return &i
	case string:
		if n == "" {
			zero := 0
			return &zero
		}
		i, err := strconv.Atoi(n)
		if err != nil {
			return nil
		}
		return &i
	}
	return nil
}

func toStringSlice(v interface{}) []string {
	switch s := v.(type) {
	case []string:
		// Filter empty strings
		var result []string
		for _, item := range s {
			item = strings.TrimSpace(item)
			if item != "" {
				result = append(result, item)
			}
		}
		return result
	case string:
		return splitLines(s)
	case []interface{}:
		var result []string
		for _, item := range s {
			if str, ok := item.(string); ok {
				str = strings.TrimSpace(str)
				if str != "" {
					result = append(result, str)
				}
			}
		}
		return result
	}
	return nil
}

func splitLines(s string) []string {
	var result []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func nilIfEmpty(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

// =============================================================================
// Host filesystem access via nsenter (for containerized deployments)
// =============================================================================

// readConfigFile reads daemon.json from the correct filesystem.
// When running in a container with host PID namespace, it reads from the
// Docker host via nsenter. Otherwise reads the local file.
func (s *Service) readConfigFile() ([]byte, error) {
	// Try local filesystem first (works on host or when file is volume-mounted)
	data, err := os.ReadFile(s.configPath)
	if err == nil && len(data) > 0 {
		return data, nil
	}

	// Local file missing or empty — try reading from host via nsenter
	if s.containerID != "" {
		if hostData, hostErr := s.readHostFile(s.configPath); hostErr == nil && len(hostData) > 0 {
			return hostData, nil
		}
	}

	// Return original result (may be os.ErrNotExist or empty data)
	return data, err
}

// writeConfigFile writes data to daemon.json on the correct filesystem.
// When running in a container with host PID namespace, it writes to the
// Docker host via nsenter. Otherwise writes locally.
func (s *Service) writeConfigFile(data []byte) error {
	if s.containerID != "" {
		return s.writeHostFile(s.configPath, data)
	}

	// Local write
	dir := filepath.Dir(s.configPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	return os.WriteFile(s.configPath, data, 0o644)
}

// configFileExists checks whether daemon.json exists (locally or on host).
func (s *Service) configFileExists() bool {
	if _, err := os.Stat(s.configPath); err == nil {
		return true
	}
	if s.containerID != "" {
		// Check host via nsenter
		_, err := s.readHostFile(s.configPath)
		return err == nil
	}
	return false
}

// readHostFile reads a file from the Docker host filesystem via nsenter.
// Uses: docker exec -u 0 <self> nsenter --target 1 --mount -- cat <path>
func (s *Service) readHostFile(path string) ([]byte, error) {
	cmd := exec.Command("docker",
		"exec", "-u", "0", s.containerID,
		"nsenter", "--target", "1", "--mount", "--",
		"cat", path,
	)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("nsenter read %s: %w", path, err)
	}
	return output, nil
}

// writeHostFile writes data to a file on the Docker host filesystem via nsenter.
// Uses: docker exec -i -u 0 <self> nsenter --target 1 --mount -- tee <path>
func (s *Service) writeHostFile(path string, data []byte) error {
	// Ensure parent directory exists on host
	dir := filepath.Dir(path)
	mkdirCmd := exec.Command("docker",
		"exec", "-u", "0", s.containerID,
		"nsenter", "--target", "1", "--mount", "--",
		"mkdir", "-p", dir,
	)
	if out, err := mkdirCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nsenter mkdir %s: %s (%w)", dir, strings.TrimSpace(string(out)), err)
	}

	// Write file content via tee
	cmd := exec.Command("docker",
		"exec", "-i", "-u", "0", s.containerID,
		"nsenter", "--target", "1", "--mount", "--",
		"tee", path,
	)
	cmd.Stdin = strings.NewReader(string(data))
	// Discard stdout (tee echoes input)
	cmd.Stdout = nil
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nsenter write %s: %s (%w)", path, strings.TrimSpace(string(out)), err)
	}
	return nil
}

// detectContainerID finds our own Docker container ID from cgroup info.
// Returns empty string if not running in a Docker container.
func detectContainerID() string {
	// Method 1: /proc/self/cgroup (cgroup v1 and v2)
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			// cgroup v1: "N:controller:/docker/<id>"
			if idx := strings.Index(line, "/docker/"); idx >= 0 {
				id := strings.TrimSpace(line[idx+len("/docker/"):])
				id = strings.TrimSuffix(id, ".scope")
				if len(id) >= 12 {
					return id[:12]
				}
			}
			// cgroup v2 systemd: "0::/system.slice/docker-<id>.scope"
			if idx := strings.Index(line, "/docker-"); idx >= 0 {
				id := line[idx+len("/docker-"):]
				id = strings.TrimSuffix(strings.TrimSpace(id), ".scope")
				if len(id) >= 12 {
					return id[:12]
				}
			}
		}
	}

	// Method 2: /proc/self/mountinfo — look for docker overlay paths
	if data, err := os.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			for _, prefix := range []string{"/docker/containers/", "/docker-", "/docker/"} {
				if idx := strings.Index(line, prefix); idx >= 0 {
					after := line[idx+len(prefix):]
					var id strings.Builder
					for _, c := range after {
						if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
							id.WriteRune(c)
						} else {
							break
						}
					}
					if id.Len() >= 12 {
						return id.String()[:12]
					}
				}
			}
		}
	}

	// Method 3: Hostname (Docker sets it to short container ID by default)
	if h, err := os.Hostname(); err == nil && len(h) == 12 {
		// Only use hostname if it looks like a hex container ID
		isHex := true
		for _, c := range h {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				isHex = false
				break
			}
		}
		if isHex {
			return h
		}
	}

	return ""
}

// isHostPIDNS checks if the container shares the host PID namespace.
// When pid:host is set, PID 1 is the host's init process (systemd/init),
// not our container's entrypoint.
func isHostPIDNS() bool {
	data, err := os.ReadFile("/proc/1/cmdline")
	if err != nil {
		return false
	}
	cmdline := string(data)
	return !strings.Contains(cmdline, "usulnet")
}
