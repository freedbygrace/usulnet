// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"fmt"
	"strings"
)

// CatalogFieldType defines the type of a configuration field.
type CatalogFieldType string

const (
	FieldText     CatalogFieldType = "text"
	FieldPassword CatalogFieldType = "password"
	FieldNumber   CatalogFieldType = "number"
	FieldSelect   CatalogFieldType = "select"
	FieldCheckbox CatalogFieldType = "checkbox"
)

// CatalogField represents a configurable field in an app template.
type CatalogField struct {
	Key         string           `json:"key"`
	Label       string           `json:"label"`
	Description string           `json:"description"`
	Type        CatalogFieldType `json:"type"`
	Default     string           `json:"default"`
	Required    bool             `json:"required"`
	Options     []string         `json:"options,omitempty"` // For select type
	Placeholder string           `json:"placeholder,omitempty"`
	Pattern     string           `json:"pattern,omitempty"` // HTML input pattern
}

// CatalogApp represents an application template in the catalog.
type CatalogApp struct {
	Slug        string         `json:"slug"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Icon        string         `json:"icon"`       // FontAwesome class
	IconColor   string         `json:"icon_color"` // Tailwind color class
	Category    string         `json:"category"`
	Version     string         `json:"version"`
	Website     string         `json:"website"`
	Source      string         `json:"source"` // GitHub URL
	Fields      []CatalogField `json:"fields"`
	ComposeTPL  string         `json:"-"` // Go template for docker-compose.yml
	Notes       string         `json:"notes,omitempty"`
}

// RenderCompose renders the docker-compose template with the given field values.
// Uses simple {{KEY}} placeholder replacement (not Go templates, to avoid complexity).
func (app *CatalogApp) RenderCompose(values map[string]string) string {
	result := app.ComposeTPL
	for _, field := range app.Fields {
		val, ok := values[field.Key]
		if !ok || val == "" {
			val = field.Default
		}
		result = strings.ReplaceAll(result, "{{"+field.Key+"}}", val)
	}

	// Gitea: append PostgreSQL service and DB environment when DB_TYPE=postgres
	if app.Slug == "gitea" && values["DB_TYPE"] == "postgres" {
		stackName := values["STACK_NAME"]
		if stackName == "" {
			stackName = "gitea"
		}
		dbPasswd := values["DB_PASSWD"]

		// Inject DB connection environment into the gitea service
		dbEnvBlock := fmt.Sprintf(`      - GITEA__database__HOST=%s-db:5432
      - GITEA__database__NAME=gitea
      - GITEA__database__USER=gitea
      - GITEA__database__PASSWD=%s`, stackName, dbPasswd)

		// Add depends_on and DB env vars to the gitea service
		result = strings.Replace(result,
			"      - GITEA__server__SSH_LISTEN_PORT=22",
			"      - GITEA__server__SSH_LISTEN_PORT=22\n"+dbEnvBlock,
			1)

		// Add depends_on before volumes section
		dependsOnBlock := fmt.Sprintf(`    depends_on:
      db:
        condition: service_healthy

  db:
    image: postgres:16-alpine
    container_name: %s-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: gitea
      POSTGRES_PASSWORD: "%s"
      POSTGRES_DB: gitea
    volumes:
      - gitea_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U gitea -d gitea"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

`, stackName, dbPasswd)

		result = strings.Replace(result, "\nvolumes:\n", "\n"+dependsOnBlock+"volumes:\n", 1)

		// Add gitea_db volume
		result = strings.Replace(result,
			"  gitea_data:\n    driver: local\n",
			"  gitea_data:\n    driver: local\n  gitea_db:\n    driver: local\n",
			1)
	}

	return result
}

// Validate checks that all required fields have values.
func (app *CatalogApp) Validate(values map[string]string) []string {
	var errors []string
	for _, f := range app.Fields {
		if f.Required {
			v := values[f.Key]
			if v == "" && f.Default == "" {
				errors = append(errors, fmt.Sprintf("'%s' is required", f.Label))
			}
		}
	}

	// Gitea: DB_PASSWD is required when using PostgreSQL
	if app.Slug == "gitea" && values["DB_TYPE"] == "postgres" && values["DB_PASSWD"] == "" {
		errors = append(errors, "'DB Password' is required when using PostgreSQL")
	}

	return errors
}

// GetDefaultValues returns a map of field keys to their default values.
func (app *CatalogApp) GetDefaultValues() map[string]string {
	vals := make(map[string]string, len(app.Fields))
	for _, f := range app.Fields {
		vals[f.Key] = f.Default
	}
	return vals
}

// ============================================================================
// Catalog Registry
// ============================================================================

// catalogApps holds all available app templates.
var catalogApps = []CatalogApp{
	// Storage
	catalogMinIO(),
	catalogNextcloud(),
	// Development
	catalogGitea(),
	catalogCodeServer(),
	catalogWoodpeckerCI(),
	// Networking
	catalogDDNSUpdater(),
	catalogNginxProxyManager(),
	catalogCaddy(),
	catalogTraefik(),
	catalogWireGuardEasy(),
	// Communication
	catalogJitsiMeet(),
	catalogMatrix(),
	catalogMattermost(),
	// Productivity
	catalogOnlyOffice(),
	// Security
	catalogPassbolt(),
	catalogVaultwarden(),
	catalogAuthentik(),
	// Monitoring
	catalogUptimeKuma(),
	catalogGrafana(),
	// Database
	catalogPostgresAdmin(),
}

// GetCatalogApps returns all available catalog apps.
func GetCatalogApps() []CatalogApp {
	return catalogApps
}

// GetCatalogApp returns a catalog app by slug, or nil if not found.
func GetCatalogApp(slug string) *CatalogApp {
	for i := range catalogApps {
		if catalogApps[i].Slug == slug {
			return &catalogApps[i]
		}
	}
	return nil
}

// GetCatalogCategories returns unique categories.
func GetCatalogCategories() []string {
	seen := make(map[string]bool)
	var cats []string
	for _, app := range catalogApps {
		if !seen[app.Category] {
			seen[app.Category] = true
			cats = append(cats, app.Category)
		}
	}
	return cats
}

// ============================================================================
// App Definitions
// ============================================================================

func catalogMinIO() CatalogApp {
	return CatalogApp{
		Slug:        "minio",
		Name:        "MinIO",
		Description: "S3-compatible object storage. High performance, Kubernetes-native.",
		Icon:        "fa-database",
		IconColor:   "text-red-400 bg-red-500/10",
		Category:    "Storage",
		Version:     "latest",
		Website:     "https://min.io",
		Source:      "https://github.com/minio/minio",
		Notes:       "After first startup, access the web console to create buckets and manage users. Default credentials are the ones you set here.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "minio",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
				Placeholder: "minio",
			},
			{
				Key:         "MINIO_ROOT_USER",
				Label:       "Root User",
				Description: "MinIO admin user",
				Type:        FieldText,
				Default:     "minioadmin",
				Required:    true,
			},
			{
				Key:         "MINIO_ROOT_PASSWORD",
				Label:       "Root Password",
				Description: "Admin password (minimum 8 characters)",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
			{
				Key:         "API_PORT",
				Label:       "API Port (S3)",
				Description: "Port for the S3-compatible API",
				Type:        FieldNumber,
				Default:     "9000",
				Required:    true,
			},
			{
				Key:         "CONSOLE_PORT",
				Label:       "Web Console Port",
				Description: "Port for the admin web interface",
				Type:        FieldNumber,
				Default:     "9001",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  minio:
    image: minio/minio:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{API_PORT}}:9000"
      - "{{CONSOLE_PORT}}:9001"
    environment:
      MINIO_ROOT_USER: "{{MINIO_ROOT_USER}}"
      MINIO_ROOT_PASSWORD: "{{MINIO_ROOT_PASSWORD}}"
    volumes:
      - minio_data:/data
    command: server /data --console-address ":9001"
    healthcheck:
      test: ["CMD", "mc", "ready", "local"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  minio_data:
    driver: local
`,
	}
}

func catalogGitea() CatalogApp {
	return CatalogApp{
		Slug:        "gitea",
		Name:        "Gitea",
		Description: "Lightweight self-hosted Git server. Simple alternative to GitLab/GitHub.",
		Icon:        "fa-code-branch",
		IconColor:   "text-green-400 bg-green-500/10",
		Category:    "Development",
		Version:     "latest",
		Website:     "https://gitea.io",
		Source:      "https://github.com/go-gitea/gitea",
		Notes:       "On first access, Gitea will show an installation wizard. If using SQLite, no external DB is needed. For PostgreSQL, make sure the database container is running first.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "gitea",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port to access the web interface",
				Type:        FieldNumber,
				Default:     "3000",
				Required:    true,
			},
			{
				Key:         "SSH_PORT",
				Label:       "SSH Port",
				Description: "Port for Git operations over SSH",
				Type:        FieldNumber,
				Default:     "2222",
				Required:    true,
			},
			{
				Key:         "DB_TYPE",
				Label:       "Database",
				Description: "Database engine to use",
				Type:        FieldSelect,
				Default:     "sqlite3",
				Required:    true,
				Options:     []string{"sqlite3", "postgres"},
			},
			{
				Key:         "DB_PASSWD",
				Label:       "DB Password (PostgreSQL only)",
				Description: "PostgreSQL password. Ignored if using SQLite.",
				Type:        FieldPassword,
				Default:     "",
				Required:    false,
				Placeholder: "only if using postgres",
			},
			{
				Key:         "DATA_PATH",
				Label:       "Data Path",
				Description: "Host directory for repositories and configuration",
				Type:        FieldText,
				Default:     "./gitea-data",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  gitea:
    image: gitea/gitea:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:3000"
      - "{{SSH_PORT}}:22"
    environment:
      - USER_UID=1000
      - USER_GID=1000
      - GITEA__database__DB_TYPE={{DB_TYPE}}
      - GITEA__server__SSH_PORT={{SSH_PORT}}
      - GITEA__server__SSH_LISTEN_PORT=22
    volumes:
      - gitea_data:/data
      - /etc/timezone:/etc/timezone:ro
      - /etc/localtime:/etc/localtime:ro

volumes:
  gitea_data:
    driver: local
`,
	}
}

func catalogDDNSUpdater() CatalogApp {
	return CatalogApp{
		Slug:        "ddns-updater",
		Name:        "DDNS Updater",
		Description: "Dynamic DNS updater. Supports Cloudflare, Namecheap, DuckDNS, OVH, and many more.",
		Icon:        "fa-globe",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://github.com/qdm12/ddns-updater",
		Source:      "https://github.com/qdm12/ddns-updater",
		Notes:       "After deployment, access the web interface to check update status. Edit the config.json file in the data path to configure your DNS providers.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "ddns-updater",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "WEB_PORT",
				Label:       "Web Port",
				Description: "Port for the status web interface",
				Type:        FieldNumber,
				Default:     "8000",
				Required:    true,
			},
			{
				Key:         "UPDATE_PERIOD",
				Label:       "Update Period",
				Description: "Interval between checks (e.g. 5m, 30m, 1h)",
				Type:        FieldText,
				Default:     "5m",
				Required:    true,
				Placeholder: "5m",
			},
			{
				Key:         "DATA_PATH",
				Label:       "Data Path",
				Description: "Host directory for configuration and data",
				Type:        FieldText,
				Default:     "./ddns-data",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  ddns-updater:
    image: qmcgaw/ddns-updater:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{WEB_PORT}}:8000"
    environment:
      - PERIOD={{UPDATE_PERIOD}}
      - TZ=Europe/Madrid
    volumes:
      - ddns_data:/updater/data

volumes:
  ddns_data:
    driver: local
`,
	}
}

func catalogNginxProxyManager() CatalogApp {
	return CatalogApp{
		Slug:        "nginx-proxy-manager",
		Name:        "Nginx Proxy Manager",
		Description: "Reverse proxy management UI with free SSL certificates. Easy to use, with Let's Encrypt support.",
		Icon:        "fa-shield-alt",
		IconColor:   "text-orange-400 bg-orange-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://nginxproxymanager.com",
		Source:      "https://github.com/NginxProxyManager/nginx-proxy-manager",
		Notes:       "Default login: admin@example.com / changeme. You will be prompted to change your email and password on first login.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "npm",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for HTTP traffic",
				Type:        FieldNumber,
				Default:     "80",
				Required:    true,
			},
			{
				Key:         "HTTPS_PORT",
				Label:       "HTTPS Port",
				Description: "Port for HTTPS traffic",
				Type:        FieldNumber,
				Default:     "443",
				Required:    true,
			},
			{
				Key:         "ADMIN_PORT",
				Label:       "Admin UI Port",
				Description: "Port for the admin web interface",
				Type:        FieldNumber,
				Default:     "81",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  npm:
    image: jc21/nginx-proxy-manager:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
      - "{{ADMIN_PORT}}:81"
    volumes:
      - npm_data:/data
      - npm_letsencrypt:/etc/letsencrypt
    healthcheck:
      test: ["CMD", "/usr/bin/check-health"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  npm_data:
    driver: local
  npm_letsencrypt:
    driver: local
`,
	}
}

func catalogCaddy() CatalogApp {
	return CatalogApp{
		Slug:        "caddy",
		Name:        "Caddy",
		Description: "Powerful, enterprise-ready web server with automatic HTTPS. Zero-config TLS certificates.",
		Icon:        "fa-lock",
		IconColor:   "text-green-400 bg-green-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://caddyserver.com",
		Source:      "https://github.com/caddyserver/caddy",
		Notes:       "Edit the Caddyfile in the data volume to configure your sites. Caddy automatically provisions TLS certificates via Let's Encrypt.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "caddy",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for HTTP traffic",
				Type:        FieldNumber,
				Default:     "80",
				Required:    true,
			},
			{
				Key:         "HTTPS_PORT",
				Label:       "HTTPS Port",
				Description: "Port for HTTPS traffic",
				Type:        FieldNumber,
				Default:     "443",
				Required:    true,
			},
			{
				Key:         "ADMIN_PORT",
				Label:       "Admin API Port",
				Description: "Port for the Caddy admin API (0 to disable)",
				Type:        FieldNumber,
				Default:     "2019",
				Required:    true,
			},
		},
		ComposeTPL: `services:
  caddy:
    image: caddy:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
      - "{{ADMIN_PORT}}:2019"
    volumes:
      - caddy_data:/data
      - caddy_config:/config
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
    environment:
      - CADDY_ADMIN=0.0.0.0:2019

volumes:
  caddy_data:
    driver: local
  caddy_config:
    driver: local
`,
	}
}

func catalogCodeServer() CatalogApp {
	return CatalogApp{
		Slug:        "code-server",
		Name:        "Code Server",
		Description: "VS Code in the browser. Full IDE experience accessible from any device with a web browser.",
		Icon:        "fa-laptop-code",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Development",
		Version:     "latest",
		Website:     "https://coder.com",
		Source:      "https://github.com/coder/code-server",
		Notes:       "Access the web interface with the password you configure. Your workspace is persisted in the data volume.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "code-server",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "WEB_PORT",
				Label:       "Web Port",
				Description: "Port to access the IDE",
				Type:        FieldNumber,
				Default:     "8443",
				Required:    true,
			},
			{
				Key:         "PASSWORD",
				Label:       "Password",
				Description: "Password to access code-server",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
			{
				Key:         "SUDO_PASSWORD",
				Label:       "Sudo Password",
				Description: "Password for sudo inside the container (optional)",
				Type:        FieldPassword,
				Default:     "",
				Required:    false,
				Placeholder: "optional",
			},
		},
		ComposeTPL: `services:
  code-server:
    image: lscr.io/linuxserver/code-server:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{WEB_PORT}}:8443"
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=Europe/Madrid
      - PASSWORD={{PASSWORD}}
      - SUDO_PASSWORD={{SUDO_PASSWORD}}
    volumes:
      - code_data:/config

volumes:
  code_data:
    driver: local
`,
	}
}

func catalogJitsiMeet() CatalogApp {
	return CatalogApp{
		Slug:        "jitsi-meet",
		Name:        "Jitsi Meet",
		Description: "Self-hosted video conferencing. Encrypted, open-source, no account required for guests.",
		Icon:        "fa-video",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Communication",
		Version:     "stable-9location9",
		Website:     "https://jitsi.org",
		Source:      "https://github.com/jitsi/docker-jitsi-meet",
		Notes:       "After deployment, access the web interface to create or join meetings. No accounts are needed by default — anyone with the URL can join. Enable authentication in the settings to require login.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "jitsi",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "PUBLIC_URL",
				Label:       "Public URL",
				Description: "Public URL where Jitsi will be accessible (e.g. https://meet.example.com)",
				Type:        FieldText,
				Default:     "",
				Required:    true,
				Placeholder: "https://meet.example.com",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for the web interface",
				Type:        FieldNumber,
				Default:     "8000",
				Required:    true,
			},
			{
				Key:         "HTTPS_PORT",
				Label:       "HTTPS Port",
				Description: "Port for HTTPS access",
				Type:        FieldNumber,
				Default:     "8443",
				Required:    true,
			},
			{
				Key:         "JVB_PORT",
				Label:       "JVB Port (UDP)",
				Description: "UDP port for video bridge media traffic",
				Type:        FieldNumber,
				Default:     "10000",
				Required:    true,
			},
			{
				Key:         "TIMEZONE",
				Label:       "Timezone",
				Description: "Container timezone",
				Type:        FieldText,
				Default:     "Europe/Madrid",
				Required:    true,
				Placeholder: "Europe/Madrid",
			},
			{
				Key:         "ENABLE_AUTH",
				Label:       "Enable Authentication",
				Description: "Require login to create rooms",
				Type:        FieldSelect,
				Default:     "0",
				Required:    true,
				Options:     []string{"0", "1"},
			},
		},
		ComposeTPL: `services:
  web:
    image: jitsi/web:stable-9location9
    container_name: {{STACK_NAME}}-web
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
    environment:
      - PUBLIC_URL={{PUBLIC_URL}}
      - TZ={{TIMEZONE}}
      - ENABLE_AUTH={{ENABLE_AUTH}}
      - ENABLE_GUESTS=1
      - ENABLE_XMPP_WEBSOCKET=1
    volumes:
      - jitsi_web_config:/config
      - jitsi_web_crontabs:/var/spool/cron/crontabs
      - jitsi_transcripts:/usr/share/jitsi-meet/transcripts
    networks:
      - jitsi

  prosody:
    image: jitsi/prosody:stable-9location9
    container_name: {{STACK_NAME}}-prosody
    restart: unless-stopped
    expose:
      - "5222"
      - "5347"
      - "5280"
    environment:
      - PUBLIC_URL={{PUBLIC_URL}}
      - TZ={{TIMEZONE}}
      - ENABLE_AUTH={{ENABLE_AUTH}}
      - ENABLE_GUESTS=1
      - ENABLE_XMPP_WEBSOCKET=1
    volumes:
      - jitsi_prosody_config:/config
      - jitsi_prosody_plugins:/prosody-plugins-custom
    networks:
      - jitsi

  jicofo:
    image: jitsi/jicofo:stable-9location9
    container_name: {{STACK_NAME}}-jicofo
    restart: unless-stopped
    environment:
      - TZ={{TIMEZONE}}
    volumes:
      - jitsi_jicofo_config:/config
    depends_on:
      - prosody
    networks:
      - jitsi

  jvb:
    image: jitsi/jvb:stable-9location9
    container_name: {{STACK_NAME}}-jvb
    restart: unless-stopped
    ports:
      - "{{JVB_PORT}}:10000/udp"
    environment:
      - TZ={{TIMEZONE}}
      - JVB_PORT={{JVB_PORT}}
    volumes:
      - jitsi_jvb_config:/config
    depends_on:
      - prosody
    networks:
      - jitsi

networks:
  jitsi:
    driver: bridge

volumes:
  jitsi_web_config:
    driver: local
  jitsi_web_crontabs:
    driver: local
  jitsi_transcripts:
    driver: local
  jitsi_prosody_config:
    driver: local
  jitsi_prosody_plugins:
    driver: local
  jitsi_jicofo_config:
    driver: local
  jitsi_jvb_config:
    driver: local
`,
	}
}

func catalogMatrix() CatalogApp {
	return CatalogApp{
		Slug:        "matrix",
		Name:        "Matrix (Synapse)",
		Description: "Decentralized, encrypted communication server. Supports chat, VoIP, and bridging to other platforms.",
		Icon:        "fa-comments",
		IconColor:   "text-emerald-400 bg-emerald-500/10",
		Category:    "Communication",
		Version:     "latest",
		Website:     "https://matrix.org",
		Source:      "https://github.com/element-hq/synapse",
		Notes:       "After deployment, register your first admin user with: docker exec -it <stack>-synapse register_new_matrix_user -c /data/homeserver.yaml -a. Connect using Element Web at the configured port, or use any Matrix client pointing to your server URL.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "matrix",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "SERVER_NAME",
				Label:       "Server Name",
				Description: "Matrix server name / domain (e.g. example.com)",
				Type:        FieldText,
				Default:     "",
				Required:    true,
				Placeholder: "example.com",
			},
			{
				Key:         "SYNAPSE_PORT",
				Label:       "Synapse Port",
				Description: "Port for the Synapse API",
				Type:        FieldNumber,
				Default:     "8008",
				Required:    true,
			},
			{
				Key:         "ELEMENT_PORT",
				Label:       "Element Web Port",
				Description: "Port for the Element web client",
				Type:        FieldNumber,
				Default:     "8009",
				Required:    true,
			},
			{
				Key:         "ENABLE_REGISTRATION",
				Label:       "Open Registration",
				Description: "Allow anyone to register an account",
				Type:        FieldSelect,
				Default:     "no",
				Required:    true,
				Options:     []string{"no", "yes"},
			},
			{
				Key:         "DB_PASSWORD",
				Label:       "Database Password",
				Description: "Password for the PostgreSQL database",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
		},
		ComposeTPL: `services:
  synapse:
    image: matrixdotorg/synapse:latest
    container_name: {{STACK_NAME}}-synapse
    restart: unless-stopped
    ports:
      - "{{SYNAPSE_PORT}}:8008"
    environment:
      - SYNAPSE_SERVER_NAME={{SERVER_NAME}}
      - SYNAPSE_REPORT_STATS=no
      - SYNAPSE_NO_TLS=1
      - SYNAPSE_ENABLE_REGISTRATION={{ENABLE_REGISTRATION}}
      - SYNAPSE_DATABASE=psycopg2
      - SYNAPSE_POSTGRES_HOST={{STACK_NAME}}-db
      - SYNAPSE_POSTGRES_PORT=5432
      - SYNAPSE_POSTGRES_DB=synapse
      - SYNAPSE_POSTGRES_USER=synapse
      - SYNAPSE_POSTGRES_PASSWORD={{DB_PASSWORD}}
    volumes:
      - synapse_data:/data
    depends_on:
      db:
        condition: service_healthy
    networks:
      - matrix

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: synapse
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: synapse
      POSTGRES_INITDB_ARGS: "--encoding=UTF-8 --lc-collate=C --lc-ctype=C"
    volumes:
      - synapse_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U synapse -d synapse"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - matrix

  element:
    image: vectorim/element-web:latest
    container_name: {{STACK_NAME}}-element
    restart: unless-stopped
    ports:
      - "{{ELEMENT_PORT}}:80"
    depends_on:
      - synapse
    networks:
      - matrix

networks:
  matrix:
    driver: bridge

volumes:
  synapse_data:
    driver: local
  synapse_db:
    driver: local
`,
	}
}

func catalogNextcloud() CatalogApp {
	return CatalogApp{
		Slug:        "nextcloud",
		Name:        "Nextcloud",
		Description: "Self-hosted file sync and share platform. Includes document editing, calendar, contacts, and 300+ apps.",
		Icon:        "fa-cloud",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Storage",
		Version:     "latest",
		Website:     "https://nextcloud.com",
		Source:      "https://github.com/nextcloud/server",
		Notes:       "On first access, complete the installation wizard. Set 'Trusted domains' to your server IP or domain in config/config.php if you get a 'trusted domain' error. The admin credentials are set during the wizard (not pre-configured here).",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "nextcloud", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "HTTP_PORT", Label: "HTTP Port", Description: "Port to access Nextcloud", Type: FieldNumber, Default: "8080", Required: true},
			{Key: "ADMIN_USER", Label: "Admin Username", Description: "Initial admin account username", Type: FieldText, Default: "admin", Required: true},
			{Key: "ADMIN_PASSWORD", Label: "Admin Password", Description: "Initial admin account password", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
			{Key: "DB_PASSWORD", Label: "Database Password", Description: "Password for the internal PostgreSQL database", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
		},
		ComposeTPL: `services:
  app:
    image: nextcloud:latest
    container_name: {{STACK_NAME}}-app
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
    environment:
      - POSTGRES_HOST={{STACK_NAME}}-db
      - POSTGRES_DB=nextcloud
      - POSTGRES_USER=nextcloud
      - POSTGRES_PASSWORD={{DB_PASSWORD}}
      - NEXTCLOUD_ADMIN_USER={{ADMIN_USER}}
      - NEXTCLOUD_ADMIN_PASSWORD={{ADMIN_PASSWORD}}
    volumes:
      - nextcloud_data:/var/www/html
    depends_on:
      db:
        condition: service_healthy
    networks:
      - nextcloud

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: nextcloud
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: nextcloud
    volumes:
      - nextcloud_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U nextcloud -d nextcloud"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - nextcloud

  redis:
    image: redis:7-alpine
    container_name: {{STACK_NAME}}-redis
    restart: unless-stopped
    networks:
      - nextcloud

networks:
  nextcloud:
    driver: bridge

volumes:
  nextcloud_data:
    driver: local
  nextcloud_db:
    driver: local
`,
	}
}

func catalogWoodpeckerCI() CatalogApp {
	return CatalogApp{
		Slug:        "woodpecker-ci",
		Name:        "Woodpecker CI",
		Description: "Simple, powerful CI/CD engine. Native Gitea integration with pipeline-as-code via .woodpecker.yml files.",
		Icon:        "fa-sitemap",
		IconColor:   "text-green-400 bg-green-500/10",
		Category:    "Development",
		Version:     "latest",
		Website:     "https://woodpecker-ci.org",
		Source:      "https://github.com/woodpecker-ci/woodpecker",
		Notes:       "Before deploying, create an OAuth2 app in Gitea: Settings → Applications → OAuth2 Apps. Set the redirect URI to http://YOUR_HOST:PORT/authorize. Copy the Client ID and Secret into the fields below. The Agent Secret is a shared secret between server and agent — generate a random string.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "woodpecker", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "HTTP_PORT", Label: "HTTP Port", Description: "Port to access the Woodpecker web UI", Type: FieldNumber, Default: "8000", Required: true},
			{Key: "WOODPECKER_HOST", Label: "Public Host URL", Description: "Public URL where Woodpecker is accessible (e.g. http://192.168.1.10:8000)", Type: FieldText, Default: "", Required: true, Placeholder: "http://your-server:8000"},
			{Key: "GITEA_URL", Label: "Gitea URL", Description: "URL of your Gitea instance", Type: FieldText, Default: "", Required: true, Placeholder: "http://gitea-server:3000"},
			{Key: "GITEA_CLIENT_ID", Label: "Gitea OAuth2 Client ID", Description: "OAuth2 app Client ID from Gitea", Type: FieldText, Default: "", Required: true},
			{Key: "GITEA_CLIENT_SECRET", Label: "Gitea OAuth2 Client Secret", Description: "OAuth2 app Client Secret from Gitea", Type: FieldPassword, Default: "", Required: true},
			{Key: "AGENT_SECRET", Label: "Agent Secret", Description: "Shared secret between server and agent (random string)", Type: FieldPassword, Default: "", Required: true, Placeholder: "random secret"},
		},
		ComposeTPL: `services:
  woodpecker-server:
    image: woodpeckerci/woodpecker-server:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:8000"
    environment:
      - WOODPECKER_OPEN=false
      - WOODPECKER_HOST={{WOODPECKER_HOST}}
      - WOODPECKER_GITEA=true
      - WOODPECKER_GITEA_URL={{GITEA_URL}}
      - WOODPECKER_GITEA_CLIENT={{GITEA_CLIENT_ID}}
      - WOODPECKER_GITEA_SECRET={{GITEA_CLIENT_SECRET}}
      - WOODPECKER_AGENT_SECRET={{AGENT_SECRET}}
      - WOODPECKER_DATABASE_DRIVER=sqlite3
      - WOODPECKER_DATABASE_DATASOURCE=/var/lib/woodpecker/woodpecker.sqlite
    volumes:
      - woodpecker_data:/var/lib/woodpecker
    networks:
      - woodpecker

  woodpecker-agent:
    image: woodpeckerci/woodpecker-agent:latest
    container_name: {{STACK_NAME}}-agent
    restart: unless-stopped
    command: agent
    environment:
      - WOODPECKER_SERVER=woodpecker-server:9000
      - WOODPECKER_AGENT_SECRET={{AGENT_SECRET}}
      - WOODPECKER_MAX_WORKFLOWS=4
      - DOCKER_HOST=unix:///var/run/docker.sock
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - woodpecker_agent:/etc/woodpecker
    depends_on:
      - woodpecker-server
    networks:
      - woodpecker

networks:
  woodpecker:
    driver: bridge

volumes:
  woodpecker_data:
    driver: local
  woodpecker_agent:
    driver: local
`,
	}
}

func catalogTraefik() CatalogApp {
	return CatalogApp{
		Slug:        "traefik",
		Name:        "Traefik",
		Description: "Cloud-native reverse proxy with automatic Docker service discovery, load balancing, and Let's Encrypt SSL.",
		Icon:        "fa-route",
		IconColor:   "text-cyan-400 bg-cyan-500/10",
		Category:    "Networking",
		Version:     "v3",
		Website:     "https://traefik.io",
		Source:      "https://github.com/traefik/traefik",
		Notes:       "The dashboard is exposed without authentication — protect it with IP allow-listing or firewall rules in production. To expose other containers, add Docker labels: traefik.enable=true, traefik.http.routers.myapp.rule=Host(`myapp.example.com`), and traefik.http.services.myapp.loadbalancer.server.port=8080.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "traefik", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "HTTP_PORT", Label: "HTTP Port", Description: "Port for incoming HTTP traffic", Type: FieldNumber, Default: "80", Required: true},
			{Key: "HTTPS_PORT", Label: "HTTPS Port", Description: "Port for incoming HTTPS traffic", Type: FieldNumber, Default: "443", Required: true},
			{Key: "DASHBOARD_PORT", Label: "Dashboard Port", Description: "Port for the Traefik web dashboard", Type: FieldNumber, Default: "8080", Required: true},
			{Key: "ACME_EMAIL", Label: "Let's Encrypt Email", Description: "Email for SSL certificate notifications from Let's Encrypt", Type: FieldText, Default: "", Required: true, Placeholder: "admin@example.com"},
		},
		ComposeTPL: `services:
  traefik:
    image: traefik:v3
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    command:
      - "--api.dashboard=true"
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.letsencrypt.acme.email={{ACME_EMAIL}}"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
      - "{{DASHBOARD_PORT}}:8080"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - traefik_letsencrypt:/letsencrypt

volumes:
  traefik_letsencrypt:
    driver: local
`,
	}
}

func catalogWireGuardEasy() CatalogApp {
	return CatalogApp{
		Slug:        "wireguard-easy",
		Name:        "WireGuard Easy",
		Description: "WireGuard VPN server with a simple web UI. Manage clients and QR codes from the browser.",
		Icon:        "fa-user-shield",
		IconColor:   "text-purple-400 bg-purple-500/10",
		Category:    "Networking",
		Version:     "latest",
		Website:     "https://github.com/wg-easy/wg-easy",
		Source:      "https://github.com/wg-easy/wg-easy",
		Notes:       "The Admin Password Hash field requires a bcrypt hash — NOT a plain text password. Generate it by running this command on your server: docker run --rm ghcr.io/wg-easy/wg-easy wgpw 'YourPassword' — then paste the output ($2b$...) into the field. WG_HOST must be your server's public IP or domain name.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "wg-easy", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "WG_HOST", Label: "Public Host", Description: "Server's public IP address or domain name (used by VPN clients)", Type: FieldText, Default: "", Required: true, Placeholder: "vpn.example.com"},
			{Key: "PASSWORD_HASH", Label: "Admin Password Hash (bcrypt)", Description: "Bcrypt hash of your admin password. Generate with: docker run --rm ghcr.io/wg-easy/wg-easy wgpw 'pass'", Type: FieldText, Default: "", Required: true, Placeholder: "$2b$12$..."},
			{Key: "WG_PORT", Label: "WireGuard UDP Port", Description: "UDP port for VPN traffic (open this in your firewall)", Type: FieldNumber, Default: "51820", Required: true},
			{Key: "UI_PORT", Label: "Web UI Port", Description: "TCP port for the admin web interface", Type: FieldNumber, Default: "51821", Required: true},
			{Key: "WG_DEFAULT_DNS", Label: "Default DNS", Description: "DNS server for VPN clients", Type: FieldText, Default: "1.1.1.1", Required: true},
		},
		ComposeTPL: `services:
  wg-easy:
    image: ghcr.io/wg-easy/wg-easy:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    environment:
      - WG_HOST={{WG_HOST}}
      - PASSWORD_HASH={{PASSWORD_HASH}}
      - WG_PORT={{WG_PORT}}
      - WG_DEFAULT_DNS={{WG_DEFAULT_DNS}}
      - WG_DEFAULT_ADDRESS=10.8.0.x
      - PORT=51821
    ports:
      - "{{WG_PORT}}:51820/udp"
      - "{{UI_PORT}}:51821/tcp"
    volumes:
      - wg_data:/etc/wireguard
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv4.ip_forward=1

volumes:
  wg_data:
    driver: local
`,
	}
}

func catalogMattermost() CatalogApp {
	return CatalogApp{
		Slug:        "mattermost",
		Name:        "Mattermost",
		Description: "Open-source team messaging platform. Slack-compatible with channels, threads, file sharing, and integrations.",
		Icon:        "fa-comments",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Communication",
		Version:     "latest",
		Website:     "https://mattermost.com",
		Source:      "https://github.com/mattermost/mattermost",
		Notes:       "After deployment, complete the setup wizard to create the system admin account. The free Team Edition supports unlimited users and message history. Configure email notifications in System Console → Environment → SMTP.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "mattermost", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "HTTP_PORT", Label: "HTTP Port", Description: "Port to access Mattermost", Type: FieldNumber, Default: "8065", Required: true},
			{Key: "SITE_URL", Label: "Site URL", Description: "Public URL where Mattermost will be accessible (e.g. http://192.168.1.10:8065)", Type: FieldText, Default: "", Required: true, Placeholder: "http://your-server:8065"},
			{Key: "DB_PASSWORD", Label: "Database Password", Description: "Password for the PostgreSQL database", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
		},
		ComposeTPL: `services:
  mattermost:
    image: mattermost/mattermost-team-edition:latest
    container_name: {{STACK_NAME}}-app
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:8065"
    environment:
      - MM_SQLSETTINGS_DRIVERNAME=postgres
      - MM_SQLSETTINGS_DATASOURCE=postgres://mattermost:{{DB_PASSWORD}}@{{STACK_NAME}}-db:5432/mattermost?sslmode=disable
      - MM_SERVICESETTINGS_SITEURL={{SITE_URL}}
      - MM_BLEVESETTINGS_INDEXDIR=/mattermost/bleve-indexes
    volumes:
      - mattermost_data:/mattermost/data
      - mattermost_logs:/mattermost/logs
      - mattermost_config:/mattermost/config
      - mattermost_bleve:/mattermost/bleve-indexes
    depends_on:
      db:
        condition: service_healthy
    networks:
      - mattermost

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: mattermost
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: mattermost
    volumes:
      - mattermost_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U mattermost -d mattermost"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - mattermost

networks:
  mattermost:
    driver: bridge

volumes:
  mattermost_data:
    driver: local
  mattermost_logs:
    driver: local
  mattermost_config:
    driver: local
  mattermost_bleve:
    driver: local
  mattermost_db:
    driver: local
`,
	}
}

func catalogPassbolt() CatalogApp {
	return CatalogApp{
		Slug:        "passbolt",
		Name:        "Passbolt",
		Description: "Open-source team password manager built for collaboration. End-to-end encrypted, audit logs, LDAP sync.",
		Icon:        "fa-key",
		IconColor:   "text-red-400 bg-red-500/10",
		Category:    "Security",
		Version:     "latest-ce",
		Website:     "https://www.passbolt.com",
		Source:      "https://github.com/passbolt/passbolt_api",
		Notes:       "After deployment, create the first admin with: docker exec -it STACK_NAME-app su -s /bin/bash -c '/usr/share/php/passbolt/bin/cake passbolt register_user -u EMAIL -f FIRST -l LAST -r admin' www-data. Email (SMTP) is required for user invitations — configure your mail provider before onboarding users.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "passbolt", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "HTTP_PORT", Label: "HTTP Port", Description: "Port for HTTP access", Type: FieldNumber, Default: "80", Required: true},
			{Key: "HTTPS_PORT", Label: "HTTPS Port", Description: "Port for HTTPS access (recommended)", Type: FieldNumber, Default: "443", Required: true},
			{Key: "DOMAIN", Label: "Domain", Description: "Domain or IP where Passbolt will be accessed (without https://)", Type: FieldText, Default: "", Required: true, Placeholder: "passwords.example.com"},
			{Key: "DB_PASSWORD", Label: "Database Password", Description: "Password for the MariaDB database", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
			{Key: "SMTP_HOST", Label: "SMTP Host", Description: "SMTP server for sending emails", Type: FieldText, Default: "smtp.example.com", Required: true, Placeholder: "smtp.gmail.com"},
			{Key: "SMTP_PORT", Label: "SMTP Port", Description: "SMTP port (587 for TLS, 465 for SSL)", Type: FieldNumber, Default: "587", Required: true},
			{Key: "EMAIL_FROM", Label: "From Email", Description: "Sender address for system emails", Type: FieldText, Default: "passbolt@example.com", Required: true},
		},
		ComposeTPL: `services:
  db:
    image: mariadb:10.11
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      MYSQL_RANDOM_ROOT_PASSWORD: "true"
      MYSQL_USER: passbolt
      MYSQL_PASSWORD: "{{DB_PASSWORD}}"
      MYSQL_DATABASE: passbolt
    volumes:
      - passbolt_db:/var/lib/mysql
    healthcheck:
      test: ["CMD", "healthcheck.sh", "--connect", "--innodb_initialized"]
      start_period: 30s
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - passbolt

  passbolt:
    image: passbolt/passbolt:latest-ce
    container_name: {{STACK_NAME}}-app
    restart: unless-stopped
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "{{HTTP_PORT}}:80"
      - "{{HTTPS_PORT}}:443"
    environment:
      APP_FULL_BASE_URL: "https://{{DOMAIN}}"
      DATASOURCES_DEFAULT_HOST: "{{STACK_NAME}}-db"
      DATASOURCES_DEFAULT_USERNAME: passbolt
      DATASOURCES_DEFAULT_PASSWORD: "{{DB_PASSWORD}}"
      DATASOURCES_DEFAULT_DATABASE: passbolt
      EMAIL_DEFAULT_FROM: "{{EMAIL_FROM}}"
      EMAIL_TRANSPORT_DEFAULT_HOST: "{{SMTP_HOST}}"
      EMAIL_TRANSPORT_DEFAULT_PORT: "{{SMTP_PORT}}"
      EMAIL_TRANSPORT_DEFAULT_TLS: "true"
    volumes:
      - passbolt_gpg:/etc/passbolt/gpg
      - passbolt_jwt:/etc/passbolt/jwt
    networks:
      - passbolt

networks:
  passbolt:
    driver: bridge

volumes:
  passbolt_db:
    driver: local
  passbolt_gpg:
    driver: local
  passbolt_jwt:
    driver: local
`,
	}
}

func catalogVaultwarden() CatalogApp {
	return CatalogApp{
		Slug:        "vaultwarden",
		Name:        "Vaultwarden",
		Description: "Lightweight Bitwarden-compatible password manager. Works with all official Bitwarden apps and browser extensions.",
		Icon:        "fa-lock",
		IconColor:   "text-indigo-400 bg-indigo-500/10",
		Category:    "Security",
		Version:     "latest",
		Website:     "https://github.com/dani-garcia/vaultwarden",
		Source:      "https://github.com/dani-garcia/vaultwarden",
		Notes:       "After deployment, register your first account via the web interface. Set SIGNUPS_ALLOWED to false after creating your accounts to prevent unauthorized registrations. Access the admin panel at /admin using the ADMIN_TOKEN.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "vaultwarden", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "WEB_PORT", Label: "Web Port", Description: "Port to access Vaultwarden", Type: FieldNumber, Default: "8081", Required: true},
			{Key: "DOMAIN", Label: "Domain URL", Description: "Full URL where Vaultwarden is accessible (needed for WebAuthn/2FA)", Type: FieldText, Default: "", Required: true, Placeholder: "https://vault.example.com"},
			{Key: "ADMIN_TOKEN", Label: "Admin Token", Description: "Secret token to access the /admin panel (use a long random string)", Type: FieldPassword, Default: "", Required: true, Placeholder: "long random secret"},
			{Key: "SIGNUPS_ALLOWED", Label: "Allow Signups", Description: "Allow new user registrations (disable after setup)", Type: FieldSelect, Default: "true", Required: true, Options: []string{"true", "false"}},
			{Key: "SMTP_HOST", Label: "SMTP Host (optional)", Description: "SMTP server for email notifications (leave empty to disable)", Type: FieldText, Default: "", Required: false, Placeholder: "smtp.example.com"},
			{Key: "SMTP_FROM", Label: "SMTP From (optional)", Description: "Sender address for email notifications", Type: FieldText, Default: "", Required: false, Placeholder: "vault@example.com"},
		},
		ComposeTPL: `services:
  vaultwarden:
    image: vaultwarden/server:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{WEB_PORT}}:80"
    environment:
      - DOMAIN={{DOMAIN}}
      - ADMIN_TOKEN={{ADMIN_TOKEN}}
      - SIGNUPS_ALLOWED={{SIGNUPS_ALLOWED}}
      - SMTP_HOST={{SMTP_HOST}}
      - SMTP_FROM={{SMTP_FROM}}
      - SMTP_PORT=587
      - SMTP_SECURITY=starttls
    volumes:
      - vw_data:/data

volumes:
  vw_data:
    driver: local
`,
	}
}

func catalogAuthentik() CatalogApp {
	return CatalogApp{
		Slug:        "authentik",
		Name:        "Authentik",
		Description: "Enterprise identity provider with SSO, OAuth2, SAML, LDAP, and SCIM. Drop-in replacement for Okta/Auth0.",
		Icon:        "fa-id-badge",
		IconColor:   "text-violet-400 bg-violet-500/10",
		Category:    "Security",
		Version:     "latest",
		Website:     "https://goauthentik.io",
		Source:      "https://github.com/goauthentik/authentik",
		Notes:       "After deployment, access the setup wizard at /if/flow/initial-setup/ to create the admin account. The SECRET_KEY must be a long random string — generate with: openssl rand -hex 32. Integrate with LDAP/AD, configure OAuth2 providers for your apps, and enable MFA for all users.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "authentik", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "HTTP_PORT", Label: "HTTP Port", Description: "Port to access Authentik", Type: FieldNumber, Default: "9000", Required: true},
			{Key: "HTTPS_PORT", Label: "HTTPS Port", Description: "Port for HTTPS access", Type: FieldNumber, Default: "9443", Required: true},
			{Key: "SECRET_KEY", Label: "Secret Key", Description: "Random secret key for session signing — generate with: openssl rand -hex 32", Type: FieldPassword, Default: "", Required: true, Placeholder: "64-char random hex"},
			{Key: "DB_PASSWORD", Label: "Database Password", Description: "Password for the PostgreSQL database", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
			{Key: "AUTHENTIK_EMAIL", Label: "Admin Email (optional)", Description: "Email address for error notifications", Type: FieldText, Default: "", Required: false, Placeholder: "admin@example.com"},
		},
		ComposeTPL: `services:
  postgresql:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: authentik
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: authentik
    volumes:
      - authentik_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U authentik -d authentik"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - authentik

  redis:
    image: redis:7-alpine
    container_name: {{STACK_NAME}}-redis
    restart: unless-stopped
    command: --save 60 1 --loglevel warning
    volumes:
      - authentik_redis:/data
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep PONG"]
      interval: 10s
      timeout: 5s
      retries: 5
    networks:
      - authentik

  server:
    image: ghcr.io/goauthentik/server:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    command: server
    environment:
      AUTHENTIK_REDIS__HOST: "{{STACK_NAME}}-redis"
      AUTHENTIK_POSTGRESQL__HOST: "{{STACK_NAME}}-db"
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: "{{DB_PASSWORD}}"
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_SECRET_KEY: "{{SECRET_KEY}}"
      AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
      AUTHENTIK_EMAIL__FROM: "{{AUTHENTIK_EMAIL}}"
    ports:
      - "{{HTTP_PORT}}:9000"
      - "{{HTTPS_PORT}}:9443"
    volumes:
      - authentik_media:/media
      - authentik_templates:/templates
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - authentik

  worker:
    image: ghcr.io/goauthentik/server:latest
    container_name: {{STACK_NAME}}-worker
    restart: unless-stopped
    command: worker
    environment:
      AUTHENTIK_REDIS__HOST: "{{STACK_NAME}}-redis"
      AUTHENTIK_POSTGRESQL__HOST: "{{STACK_NAME}}-db"
      AUTHENTIK_POSTGRESQL__USER: authentik
      AUTHENTIK_POSTGRESQL__PASSWORD: "{{DB_PASSWORD}}"
      AUTHENTIK_POSTGRESQL__NAME: authentik
      AUTHENTIK_SECRET_KEY: "{{SECRET_KEY}}"
      AUTHENTIK_ERROR_REPORTING__ENABLED: "false"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - authentik_media:/media
      - authentik_certs:/certs
      - authentik_templates:/templates
    depends_on:
      postgresql:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - authentik

networks:
  authentik:
    driver: bridge

volumes:
  authentik_db:
    driver: local
  authentik_redis:
    driver: local
  authentik_media:
    driver: local
  authentik_certs:
    driver: local
  authentik_templates:
    driver: local
`,
	}
}

func catalogUptimeKuma() CatalogApp {
	return CatalogApp{
		Slug:        "uptime-kuma",
		Name:        "Uptime Kuma",
		Description: "Self-hosted uptime monitoring with beautiful status pages. HTTP, TCP, DNS, Docker, and ping monitors.",
		Icon:        "fa-heartbeat",
		IconColor:   "text-green-400 bg-green-500/10",
		Category:    "Monitoring",
		Version:     "latest",
		Website:     "https://uptime.kuma.pet",
		Source:      "https://github.com/louislam/uptime-kuma",
		Notes:       "On first access, create an admin account. Add monitors for your services (URLs, ports, Docker containers) and configure notification channels (Slack, Telegram, email, webhook, and many more). Create a public status page to share service health with your team or customers.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "uptime-kuma", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "WEB_PORT", Label: "Web Port", Description: "Port to access the Uptime Kuma dashboard", Type: FieldNumber, Default: "3001", Required: true},
		},
		ComposeTPL: `services:
  uptime-kuma:
    image: louislam/uptime-kuma:latest
    container_name: {{STACK_NAME}}
    restart: unless-stopped
    ports:
      - "{{WEB_PORT}}:3001"
    volumes:
      - kuma_data:/app/data
      - /var/run/docker.sock:/var/run/docker.sock:ro

volumes:
  kuma_data:
    driver: local
`,
	}
}

func catalogGrafana() CatalogApp {
	return CatalogApp{
		Slug:        "grafana",
		Name:        "Grafana + Prometheus",
		Description: "Industry-standard metrics stack. Prometheus collects and stores metrics; Grafana visualizes them with rich dashboards.",
		Icon:        "fa-chart-line",
		IconColor:   "text-orange-400 bg-orange-500/10",
		Category:    "Monitoring",
		Version:     "latest",
		Website:     "https://grafana.com",
		Source:      "https://github.com/grafana/grafana",
		Notes:       "Default Grafana login: admin / admin (you'll be prompted to change it). Add Prometheus as a data source at http://STACK_NAME-prometheus:9090. Import community dashboards from grafana.com/dashboards — ID 1860 (Node Exporter Full) is a popular starting point. Add node-exporter to monitor host metrics.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "monitoring", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "GRAFANA_PORT", Label: "Grafana Port", Description: "Port for the Grafana dashboard", Type: FieldNumber, Default: "3000", Required: true},
			{Key: "PROMETHEUS_PORT", Label: "Prometheus Port", Description: "Port for the Prometheus UI and API", Type: FieldNumber, Default: "9090", Required: true},
			{Key: "ADMIN_USER", Label: "Grafana Admin User", Description: "Grafana initial admin username", Type: FieldText, Default: "admin", Required: true},
			{Key: "ADMIN_PASSWORD", Label: "Grafana Admin Password", Description: "Grafana initial admin password", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
		},
		ComposeTPL: `services:
  grafana:
    image: grafana/grafana:latest
    container_name: {{STACK_NAME}}-grafana
    restart: unless-stopped
    ports:
      - "{{GRAFANA_PORT}}:3000"
    environment:
      - GF_SECURITY_ADMIN_USER={{ADMIN_USER}}
      - GF_SECURITY_ADMIN_PASSWORD={{ADMIN_PASSWORD}}
      - GF_USERS_ALLOW_SIGN_UP=false
    volumes:
      - grafana_data:/var/lib/grafana
    depends_on:
      - prometheus
    networks:
      - monitoring

  prometheus:
    image: prom/prometheus:latest
    container_name: {{STACK_NAME}}-prometheus
    restart: unless-stopped
    ports:
      - "{{PROMETHEUS_PORT}}:9090"
    command:
      - "--config.file=/etc/prometheus/prometheus.yml"
      - "--storage.tsdb.path=/prometheus"
      - "--storage.tsdb.retention.time=30d"
      - "--web.console.libraries=/usr/share/prometheus/console_libraries"
      - "--web.console.templates=/usr/share/prometheus/consoles"
    configs:
      - source: prometheus_yml
        target: /etc/prometheus/prometheus.yml
    volumes:
      - prometheus_data:/prometheus
    networks:
      - monitoring

  node-exporter:
    image: prom/node-exporter:latest
    container_name: {{STACK_NAME}}-node-exporter
    restart: unless-stopped
    command:
      - "--path.rootfs=/host"
    volumes:
      - /:/host:ro,rslave
    networks:
      - monitoring

configs:
  prometheus_yml:
    content: |
      global:
        scrape_interval: 15s
        evaluation_interval: 15s
      scrape_configs:
        - job_name: prometheus
          static_configs:
            - targets: ['localhost:9090']
        - job_name: node-exporter
          static_configs:
            - targets: ['{{STACK_NAME}}-node-exporter:9100']

networks:
  monitoring:
    driver: bridge

volumes:
  grafana_data:
    driver: local
  prometheus_data:
    driver: local
`,
	}
}

func catalogPostgresAdmin() CatalogApp {
	return CatalogApp{
		Slug:        "postgres-admin",
		Name:        "PostgreSQL + pgAdmin",
		Description: "Production-ready PostgreSQL database with pgAdmin 4 web management UI. Ideal for shared database hosting.",
		Icon:        "fa-database",
		IconColor:   "text-blue-400 bg-blue-500/10",
		Category:    "Database",
		Version:     "16",
		Website:     "https://www.postgresql.org",
		Source:      "https://github.com/postgres/postgres",
		Notes:       "pgAdmin connects to the database automatically via the internal network. Use pgAdmin to create additional databases, users, and manage schemas. To connect external applications, use port PG_PORT with user PG_USER and the password configured here.",
		Fields: []CatalogField{
			{Key: "STACK_NAME", Label: "Stack Name", Description: "Name to identify this stack", Type: FieldText, Default: "postgres", Required: true, Pattern: "^[a-z0-9][a-z0-9_-]*$"},
			{Key: "PG_PORT", Label: "PostgreSQL Port", Description: "Port to expose PostgreSQL to host (5432 is standard)", Type: FieldNumber, Default: "5432", Required: true},
			{Key: "PG_USER", Label: "DB Username", Description: "PostgreSQL superuser username", Type: FieldText, Default: "postgres", Required: true},
			{Key: "PG_PASSWORD", Label: "DB Password", Description: "PostgreSQL superuser password", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
			{Key: "PG_DB", Label: "Default Database", Description: "Name of the initial database to create", Type: FieldText, Default: "postgres", Required: true},
			{Key: "PGADMIN_PORT", Label: "pgAdmin Port", Description: "Port to access the pgAdmin web interface", Type: FieldNumber, Default: "5050", Required: true},
			{Key: "PGADMIN_EMAIL", Label: "pgAdmin Email", Description: "Email address to log in to pgAdmin", Type: FieldText, Default: "", Required: true, Placeholder: "admin@example.com"},
			{Key: "PGADMIN_PASSWORD", Label: "pgAdmin Password", Description: "Password to log in to pgAdmin", Type: FieldPassword, Default: "", Required: true, Placeholder: "secure password"},
		},
		ComposeTPL: `services:
  postgres:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    ports:
      - "{{PG_PORT}}:5432"
    environment:
      POSTGRES_USER: "{{PG_USER}}"
      POSTGRES_PASSWORD: "{{PG_PASSWORD}}"
      POSTGRES_DB: "{{PG_DB}}"
    volumes:
      - pg_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U {{PG_USER}} -d {{PG_DB}}"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - postgres

  pgadmin:
    image: dpage/pgadmin4:latest
    container_name: {{STACK_NAME}}-pgadmin
    restart: unless-stopped
    ports:
      - "{{PGADMIN_PORT}}:80"
    environment:
      PGADMIN_DEFAULT_EMAIL: "{{PGADMIN_EMAIL}}"
      PGADMIN_DEFAULT_PASSWORD: "{{PGADMIN_PASSWORD}}"
      PGADMIN_CONFIG_SERVER_MODE: "False"
    volumes:
      - pgadmin_data:/var/lib/pgadmin
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - postgres

networks:
  postgres:
    driver: bridge

volumes:
  pg_data:
    driver: local
  pgadmin_data:
    driver: local
`,
	}
}

func catalogOnlyOffice() CatalogApp {
	return CatalogApp{
		Slug:        "onlyoffice",
		Name:        "OnlyOffice",
		Description: "Self-hosted office suite. Document, spreadsheet, and presentation editor with real-time collaboration.",
		Icon:        "fa-file-word",
		IconColor:   "text-orange-400 bg-orange-500/10",
		Category:    "Productivity",
		Version:     "latest",
		Website:     "https://www.onlyoffice.com",
		Source:      "https://github.com/ONLYOFFICE/DocumentServer",
		Notes:       "After deployment, the Document Server is available at the configured port. Integrate it with Nextcloud, ownCloud, or any other platform that supports ONLYOFFICE. Use the JWT secret to authenticate connections from your integrations.",
		Fields: []CatalogField{
			{
				Key:         "STACK_NAME",
				Label:       "Stack Name",
				Description: "Name to identify this stack",
				Type:        FieldText,
				Default:     "onlyoffice",
				Required:    true,
				Pattern:     "^[a-z0-9][a-z0-9_-]*$",
			},
			{
				Key:         "HTTP_PORT",
				Label:       "HTTP Port",
				Description: "Port for the Document Server web interface",
				Type:        FieldNumber,
				Default:     "8080",
				Required:    true,
			},
			{
				Key:         "JWT_SECRET",
				Label:       "JWT Secret",
				Description: "Secret key for authenticating integration requests",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure secret",
			},
			{
				Key:         "DB_PASSWORD",
				Label:       "Database Password",
				Description: "Password for the PostgreSQL database",
				Type:        FieldPassword,
				Default:     "",
				Required:    true,
				Placeholder: "secure password",
			},
		},
		ComposeTPL: `services:
  documentserver:
    image: onlyoffice/documentserver:latest
    container_name: {{STACK_NAME}}-server
    restart: unless-stopped
    ports:
      - "{{HTTP_PORT}}:80"
    environment:
      - JWT_ENABLED=true
      - JWT_SECRET={{JWT_SECRET}}
      - DB_TYPE=postgres
      - DB_HOST={{STACK_NAME}}-db
      - DB_PORT=5432
      - DB_NAME=onlyoffice
      - DB_USER=onlyoffice
      - DB_PWD={{DB_PASSWORD}}
      - AMQP_URI=amqp://guest:guest@{{STACK_NAME}}-rabbitmq
    volumes:
      - onlyoffice_data:/var/www/onlyoffice/Data
      - onlyoffice_logs:/var/log/onlyoffice
    depends_on:
      db:
        condition: service_healthy
      rabbitmq:
        condition: service_healthy
    networks:
      - onlyoffice

  db:
    image: postgres:16-alpine
    container_name: {{STACK_NAME}}-db
    restart: unless-stopped
    environment:
      POSTGRES_USER: onlyoffice
      POSTGRES_PASSWORD: "{{DB_PASSWORD}}"
      POSTGRES_DB: onlyoffice
    volumes:
      - onlyoffice_db:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U onlyoffice -d onlyoffice"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s
    networks:
      - onlyoffice

  rabbitmq:
    image: rabbitmq:3-alpine
    container_name: {{STACK_NAME}}-rabbitmq
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "-q", "ping"]
      interval: 15s
      timeout: 10s
      retries: 5
      start_period: 30s
    networks:
      - onlyoffice

networks:
  onlyoffice:
    driver: bridge

volumes:
  onlyoffice_data:
    driver: local
  onlyoffice_logs:
    driver: local
  onlyoffice_db:
    driver: local
`,
	}
}
