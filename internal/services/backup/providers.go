// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package backup provides backup and restore services.
// This file contains providers that integrate with Department E services.
package backup

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	containerservice "github.com/fr4nsys/usulnet/internal/services/container"
	hostservice "github.com/fr4nsys/usulnet/internal/services/host"
	stackservice "github.com/fr4nsys/usulnet/internal/services/stack"
	volumeservice "github.com/fr4nsys/usulnet/internal/services/volume"
)

// ============================================================================
// Volume Provider
// ============================================================================

// DockerVolumeProvider provides volume operations for backup service.
// Implements VolumeProvider interface using Dept E's volume.Service.
type DockerVolumeProvider struct {
	hostService   *hostservice.Service
	volumeService *volumeservice.Service
}

// NewDockerVolumeProvider creates a new Docker volume provider.
func NewDockerVolumeProvider(
	hostService *hostservice.Service,
	volumeService *volumeservice.Service,
) *DockerVolumeProvider {
	return &DockerVolumeProvider{
		hostService:   hostService,
		volumeService: volumeService,
	}
}

// GetVolume retrieves volume information.
func (p *DockerVolumeProvider) GetVolume(ctx context.Context, hostID uuid.UUID, name string) (*VolumeInfo, error) {
	vol, err := p.volumeService.Get(ctx, hostID, name)
	if err != nil {
		return nil, fmt.Errorf("get volume %s: %w", name, err)
	}

	return &VolumeInfo{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Labels:     vol.Labels,
		Options:    vol.Options,
		Scope:      string(vol.Scope),
		CreatedAt:  vol.CreatedAt,
	}, nil
}

// GetVolumeMountpoint returns the host path where the volume is mounted.
func (p *DockerVolumeProvider) GetVolumeMountpoint(ctx context.Context, hostID uuid.UUID, name string) (string, error) {
	vol, err := p.volumeService.Get(ctx, hostID, name)
	if err != nil {
		return "", fmt.Errorf("get volume mountpoint %s: %w", name, err)
	}

	if vol.Mountpoint == "" {
		return "", fmt.Errorf("volume %s has no mountpoint", name)
	}

	return vol.Mountpoint, nil
}

// VolumeExists checks if a volume exists.
func (p *DockerVolumeProvider) VolumeExists(ctx context.Context, hostID uuid.UUID, name string) (bool, error) {
	return p.volumeService.Exists(ctx, hostID, name)
}

// CreateVolume creates a new volume for restore operations.
func (p *DockerVolumeProvider) CreateVolume(ctx context.Context, hostID uuid.UUID, opts CreateVolumeOptions) (*VolumeInfo, error) {
	vol, err := p.volumeService.Create(ctx, hostID, &models.CreateVolumeInput{
		Name:       opts.Name,
		Driver:     opts.Driver,
		DriverOpts: opts.DriverOpts,
		Labels:     opts.Labels,
	})
	if err != nil {
		return nil, fmt.Errorf("create volume %s: %w", opts.Name, err)
	}

	return &VolumeInfo{
		Name:       vol.Name,
		Driver:     vol.Driver,
		Mountpoint: vol.Mountpoint,
		Labels:     vol.Labels,
		Options:    vol.Options,
		Scope:      string(vol.Scope),
		CreatedAt:  vol.CreatedAt,
	}, nil
}

// ListVolumes lists all volumes on a host.
func (p *DockerVolumeProvider) ListVolumes(ctx context.Context, hostID uuid.UUID) ([]*VolumeInfo, error) {
	volumes, err := p.volumeService.List(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("list volumes: %w", err)
	}

	result := make([]*VolumeInfo, 0, len(volumes))
	for _, vol := range volumes {
		result = append(result, &VolumeInfo{
			Name:       vol.Name,
			Driver:     vol.Driver,
			Mountpoint: vol.Mountpoint,
			Labels:     vol.Labels,
			Options:    vol.Options,
			Scope:      string(vol.Scope),
			CreatedAt:  vol.CreatedAt,
		})
	}

	return result, nil
}

// CopyVolumeData copies volume data to a destination directory using Docker API.
// This is used when the volume mountpoint is not accessible from the local filesystem
// (e.g., when running inside a Docker container).
func (p *DockerVolumeProvider) CopyVolumeData(ctx context.Context, hostID uuid.UUID, volumeName string, destPath string) error {
	client, err := p.hostService.GetClient(ctx, hostID)
	if err != nil {
		return fmt.Errorf("get docker client: %w", err)
	}

	// Create a temporary helper container that mounts the volume
	helperName := fmt.Sprintf("usulnet-backup-helper-%s", volumeName)
	containerID, err := client.ContainerCreate(ctx, docker.ContainerCreateOptions{
		Name:   helperName,
		Image:  "busybox:latest",
		Cmd:    []string{"true"},
		Binds:  []string{volumeName + ":/backup-data:ro"},
		Labels: map[string]string{"usulnet.backup-helper": "true"},
	})
	if err != nil {
		return fmt.Errorf("create helper container: %w", err)
	}

	// Always clean up the helper container
	defer func() {
		_ = client.ContainerRemove(ctx, containerID, true, false)
	}()

	// Copy data from the helper container using Docker API
	reader, _, err := client.ContainerCopyFromContainer(ctx, containerID, "/backup-data")
	if err != nil {
		return fmt.Errorf("copy from container: %w", err)
	}
	defer reader.Close()

	// Extract the tar stream to the destination path
	return extractTar(reader, destPath, "backup-data")
}

// extractTar extracts a tar stream to a destination directory, stripping the given prefix.
func extractTar(r io.Reader, destPath string, stripPrefix string) error {
	tr := tar.NewReader(r)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		// Strip the prefix directory from the path
		name := header.Name
		if stripPrefix != "" {
			rel, err := filepath.Rel(stripPrefix, name)
			if err != nil || rel == "." {
				continue
			}
			name = rel
		}

		target := filepath.Join(destPath, name)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("create dir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent dir: %w", err)
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			f.Close()
		case tar.TypeSymlink:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent dir: %w", err)
			}
			if err := os.Symlink(header.Linkname, target); err != nil {
				return fmt.Errorf("create symlink %s: %w", target, err)
			}
		}
	}
	return nil
}

// VolumeInfo contains volume information for backup operations.
type VolumeInfo struct {
	Name       string
	Driver     string
	Mountpoint string
	Labels     map[string]string
	Options    map[string]string
	Scope      string
	CreatedAt  time.Time
}

// CreateVolumeOptions contains options for creating a volume.
type CreateVolumeOptions struct {
	Name       string
	Driver     string
	DriverOpts map[string]string
	Labels     map[string]string
}

// ============================================================================
// Container Provider
// ============================================================================

// DockerContainerProvider provides container operations for backup service.
// Implements ContainerProvider interface using Dept E's container.Service.
type DockerContainerProvider struct {
	hostService      *hostservice.Service
	containerService *containerservice.Service
}

// NewDockerContainerProvider creates a new Docker container provider.
func NewDockerContainerProvider(
	hostService *hostservice.Service,
	containerService *containerservice.Service,
) *DockerContainerProvider {
	return &DockerContainerProvider{
		hostService:      hostService,
		containerService: containerService,
	}
}

// GetContainer retrieves container information.
func (p *DockerContainerProvider) GetContainer(ctx context.Context, hostID uuid.UUID, containerID string) (*ContainerInfo, error) {
	container, err := p.containerService.Get(ctx, hostID, containerID)
	if err != nil {
		return nil, fmt.Errorf("get container %s: %w", containerID, err)
	}

	return containerToInfo(container), nil
}

// GetContainerByName retrieves container by name.
func (p *DockerContainerProvider) GetContainerByName(ctx context.Context, hostID uuid.UUID, name string) (*ContainerInfo, error) {
	container, err := p.containerService.GetByName(ctx, hostID, name)
	if err != nil {
		return nil, fmt.Errorf("get container by name %s: %w", name, err)
	}

	return containerToInfo(container), nil
}

// StopContainer stops a container for backup.
func (p *DockerContainerProvider) StopContainer(ctx context.Context, hostID uuid.UUID, containerID string, timeout *int) error {
	// Note: timeout is ignored, using service default
	if err := p.containerService.StopContainer(ctx, hostID, containerID); err != nil {
		return fmt.Errorf("stop container %s: %w", containerID, err)
	}
	return nil
}

// StartContainer starts a container after backup/restore.
func (p *DockerContainerProvider) StartContainer(ctx context.Context, hostID uuid.UUID, containerID string) error {
	if err := p.containerService.StartContainer(ctx, hostID, containerID); err != nil {
		return fmt.Errorf("start container %s: %w", containerID, err)
	}
	return nil
}

// IsContainerRunning checks if a container is running.
func (p *DockerContainerProvider) IsContainerRunning(ctx context.Context, hostID uuid.UUID, containerID string) (bool, error) {
	container, err := p.containerService.Get(ctx, hostID, containerID)
	if err != nil {
		return false, err
	}
	return container.State == models.ContainerStateRunning, nil
}

// ListContainersUsingVolume lists containers that have a volume mounted.
// Note: This is a simplified implementation that lists all containers and filters by mounts
func (p *DockerContainerProvider) ListContainersUsingVolume(ctx context.Context, hostID uuid.UUID, volumeName string) ([]*ContainerInfo, error) {
	containers, err := p.containerService.ListByHost(ctx, hostID)
	if err != nil {
		return nil, fmt.Errorf("list containers: %w", err)
	}

	result := make([]*ContainerInfo, 0)
	for _, c := range containers {
		for _, mount := range c.Mounts {
			if mount.Source == volumeName || mount.Destination == volumeName {
				result = append(result, containerToInfo(c))
				break
			}
		}
	}

	return result, nil
}

// ContainerInfo contains container information for backup operations.
type ContainerInfo struct {
	ID      string
	Name    string
	Image   string
	State   string
	Status  string
	Volumes []string
	Labels  map[string]string
}

func containerToInfo(c *models.Container) *ContainerInfo {
	// Extract volume names from mounts
	var volumes []string
	for _, m := range c.Mounts {
		if m.Type == "volume" {
			volumes = append(volumes, m.Source)
		}
	}
	return &ContainerInfo{
		ID:      c.ID,
		Name:    c.Name,
		Image:   c.Image,
		State:   string(c.State),
		Status:  c.Status,
		Volumes: volumes,
		Labels:  c.Labels,
	}
}

// ============================================================================
// Provider Interfaces (for dependency injection)
// ============================================================================

// VolumeProvider interface for backup service dependency injection.
type VolumeProvider interface {
	GetVolume(ctx context.Context, hostID uuid.UUID, name string) (*VolumeInfo, error)
	GetVolumeMountpoint(ctx context.Context, hostID uuid.UUID, name string) (string, error)
	VolumeExists(ctx context.Context, hostID uuid.UUID, name string) (bool, error)
	CreateVolume(ctx context.Context, hostID uuid.UUID, opts CreateVolumeOptions) (*VolumeInfo, error)
	ListVolumes(ctx context.Context, hostID uuid.UUID) ([]*VolumeInfo, error)
	// CopyVolumeData copies volume contents to destPath using Docker API.
	// Used when the volume mountpoint is not accessible from the local filesystem.
	CopyVolumeData(ctx context.Context, hostID uuid.UUID, volumeName string, destPath string) error
}

// ContainerProvider interface for backup service dependency injection.
type ContainerProvider interface {
	GetContainer(ctx context.Context, hostID uuid.UUID, containerID string) (*ContainerInfo, error)
	GetContainerByName(ctx context.Context, hostID uuid.UUID, name string) (*ContainerInfo, error)
	StopContainer(ctx context.Context, hostID uuid.UUID, containerID string, timeout *int) error
	StartContainer(ctx context.Context, hostID uuid.UUID, containerID string) error
	IsContainerRunning(ctx context.Context, hostID uuid.UUID, containerID string) (bool, error)
	ListContainersUsingVolume(ctx context.Context, hostID uuid.UUID, volumeName string) ([]*ContainerInfo, error)
}

// ============================================================================
// Stack Provider
// ============================================================================

// DockerStackProvider provides stack operations for backup service.
// Implements StackProvider interface using the stack service.
type DockerStackProvider struct {
	stackService     *stackservice.Service
	containerService *containerservice.Service
}

// NewDockerStackProvider creates a new Docker stack provider.
func NewDockerStackProvider(
	stackService *stackservice.Service,
	containerService *containerservice.Service,
) *DockerStackProvider {
	return &DockerStackProvider{
		stackService:     stackService,
		containerService: containerService,
	}
}

// GetStack retrieves a stack by ID.
func (p *DockerStackProvider) GetStack(ctx context.Context, id uuid.UUID) (*StackInfo, error) {
	stack, err := p.stackService.Get(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get stack %s: %w", id, err)
	}

	var serviceNames []string
	for _, svc := range stack.Services {
		serviceNames = append(serviceNames, svc.Name)
	}

	return &StackInfo{
		ID:          stack.ID,
		HostID:      stack.HostID,
		Name:        stack.Name,
		ComposeFile: stack.ComposeFile,
		EnvFile:     stack.EnvFile,
		Services:    serviceNames,
		Labels:      stack.Variables,
	}, nil
}

// GetStackContainers retrieves containers belonging to a stack.
func (p *DockerStackProvider) GetStackContainers(ctx context.Context, id uuid.UUID) ([]StackContainerInfo, error) {
	containers, err := p.stackService.GetContainers(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get stack containers for %s: %w", id, err)
	}

	result := make([]StackContainerInfo, 0, len(containers))
	for _, c := range containers {
		var volumes []string
		for _, m := range c.Mounts {
			if m.Type == "volume" {
				volumes = append(volumes, m.Source)
			}
		}
		result = append(result, StackContainerInfo{
			ID:      c.ID,
			Name:    c.Name,
			Image:   c.Image,
			Volumes: volumes,
			Labels:  c.Labels,
		})
	}

	return result, nil
}

// Verify interface compliance at compile time
var _ VolumeProvider = (*DockerVolumeProvider)(nil)
var _ ContainerProvider = (*DockerContainerProvider)(nil)
var _ StackProvider = (*DockerStackProvider)(nil)
