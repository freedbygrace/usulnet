// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	"github.com/fr4nsys/usulnet/internal/web/templates/pages/calendar"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/tools"
)

// ============================================================================
// Dev Tools Handlers
// ============================================================================

// toolsData prepares the common ToolsData for all tool pages.
func (h *Handler) toolsData(r *http.Request, title string) tools.ToolsData {
	return tools.ToolsData{
		PageData: h.prepareTemplPageData(r, title, "tools"),
	}
}

// ToolsIndex renders the tools listing page.
// GET /tools
func (h *Handler) ToolsIndex(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.ToolsList(h.toolsData(r, "Dev Tools")))
}

// --- Crypto & Security ---

// ToolToken renders the token generator page.
// GET /tools/token
func (h *Handler) ToolToken(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.TokenGenerator(h.toolsData(r, "Token Generator")))
}

// ToolHash renders the hash generator page.
// GET /tools/hash
func (h *Handler) ToolHash(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.HashGenerator(h.toolsData(r, "Hash Generator")))
}

// ToolBcrypt renders the bcrypt tool page.
// GET /tools/bcrypt
func (h *Handler) ToolBcrypt(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.BcryptTool(h.toolsData(r, "Bcrypt")))
}

// ToolHMAC renders the HMAC generator page.
// GET /tools/hmac
func (h *Handler) ToolHMAC(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.HMACGenerator(h.toolsData(r, "HMAC Generator")))
}

// ToolEncrypt renders the AES encryption page.
// GET /tools/encrypt
func (h *Handler) ToolEncrypt(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.AESEncrypt(h.toolsData(r, "AES Encrypt / Decrypt")))
}

// ToolPassword renders the password strength analyzer page.
// GET /tools/password
func (h *Handler) ToolPassword(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.PasswordStrength(h.toolsData(r, "Password Strength")))
}

// ToolRSA renders the RSA key generator page.
// GET /tools/rsa
func (h *Handler) ToolRSA(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.RSAKeyGenerator(h.toolsData(r, "RSA Key Generator")))
}

// --- Generators ---

// ToolUUID renders the UUID generator page.
// GET /tools/uuid
func (h *Handler) ToolUUID(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.UUIDGenerator(h.toolsData(r, "UUID Generator")))
}

// ToolULID renders the ULID generator page.
// GET /tools/ulid
func (h *Handler) ToolULID(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.ULIDGenerator(h.toolsData(r, "ULID Generator")))
}

// ToolLorem renders the lorem ipsum generator page.
// GET /tools/lorem
func (h *Handler) ToolLorem(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.LoremIpsum(h.toolsData(r, "Lorem Ipsum")))
}

// ToolCrontab renders the crontab builder page.
// GET /tools/crontab
func (h *Handler) ToolCrontab(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.CrontabBuilder(h.toolsData(r, "Crontab Builder")))
}

// ToolPort renders the random port generator page.
// GET /tools/port
func (h *Handler) ToolPort(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.RandomPort(h.toolsData(r, "Random Port Generator")))
}

// ToolQRCode renders the QR code generator page.
// GET /tools/qrcode
func (h *Handler) ToolQRCode(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.QRCodeGenerator(h.toolsData(r, "QR Code Generator")))
}

// --- Encoders & Decoders ---

// ToolBase64 renders the Base64 encoder/decoder page.
// GET /tools/base64
func (h *Handler) ToolBase64(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.Base64Tool(h.toolsData(r, "Base64")))
}

// ToolURLEncode renders the URL encode/decode page.
// GET /tools/url-encode
func (h *Handler) ToolURLEncode(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.URLEncodeDecode(h.toolsData(r, "URL Encode / Decode")))
}

// ToolHTMLEntities renders the HTML entities encoder/decoder page.
// GET /tools/html-entities
func (h *Handler) ToolHTMLEntities(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.HTMLEntities(h.toolsData(r, "HTML Entities")))
}

// ToolJWT renders the JWT parser page.
// GET /tools/jwt
func (h *Handler) ToolJWT(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.JWTParser(h.toolsData(r, "JWT Parser")))
}

// ToolBasicAuth renders the basic auth generator page.
// GET /tools/basic-auth
func (h *Handler) ToolBasicAuth(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.BasicAuthGenerator(h.toolsData(r, "Basic Auth Generator")))
}

// --- Converters ---

// ToolJSONYAML renders the JSON/YAML converter page.
// GET /tools/json-yaml
func (h *Handler) ToolJSONYAML(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.JSONYAMLConverter(h.toolsData(r, "JSON ↔ YAML")))
}

// ToolJSONTOML renders the JSON/TOML converter page.
// GET /tools/json-toml
func (h *Handler) ToolJSONTOML(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.JSONTOMLConverter(h.toolsData(r, "JSON ↔ TOML")))
}

// ToolYAMLTOML renders the YAML/TOML converter page.
// GET /tools/yaml-toml
func (h *Handler) ToolYAMLTOML(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.YAMLTOMLConverter(h.toolsData(r, "YAML ↔ TOML")))
}

// ToolBaseConverter renders the number base converter page.
// GET /tools/base-converter
func (h *Handler) ToolBaseConverter(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.BaseConverter(h.toolsData(r, "Number Base Converter")))
}

// ToolColor renders the color converter page.
// GET /tools/color
func (h *Handler) ToolColor(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.ColorConverter(h.toolsData(r, "Color Converter")))
}

// ToolDatetime renders the datetime converter page.
// GET /tools/datetime
func (h *Handler) ToolDatetime(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.DatetimeConverter(h.toolsData(r, "Datetime Converter")))
}

// ToolCase renders the case converter page.
// GET /tools/case
func (h *Handler) ToolCase(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.CaseConverter(h.toolsData(r, "Case Converter")))
}

// --- Formatters ---

// ToolJSONFormat renders the JSON prettify/minify page.
// GET /tools/json-format
func (h *Handler) ToolJSONFormat(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.JSONFormat(h.toolsData(r, "JSON Prettify")))
}

// ToolSQLFormat renders the SQL formatter page.
// GET /tools/sql-format
func (h *Handler) ToolSQLFormat(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.SQLFormatter(h.toolsData(r, "SQL Formatter")))
}

// ToolXMLFormat renders the XML formatter page.
// GET /tools/xml-format
func (h *Handler) ToolXMLFormat(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.XMLFormatter(h.toolsData(r, "XML Formatter")))
}

// ToolYAMLFormat renders the YAML formatter page.
// GET /tools/yaml-format
func (h *Handler) ToolYAMLFormat(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.YAMLFormatter(h.toolsData(r, "YAML Formatter")))
}

// ToolJSONCSV renders the JSON-to-CSV converter page.
// GET /tools/json-csv
func (h *Handler) ToolJSONCSV(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.JSONToCSV(h.toolsData(r, "JSON to CSV")))
}

// --- Network ---

// ToolSubnet renders the IPv4 subnet calculator page.
// GET /tools/subnet
func (h *Handler) ToolSubnet(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.SubnetCalculator(h.toolsData(r, "IPv4 Subnet Calculator")))
}

// ToolIPv4Convert renders the IPv4 converter page.
// GET /tools/ipv4-convert
func (h *Handler) ToolIPv4Convert(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.IPv4Converter(h.toolsData(r, "IPv4 Converter")))
}

// ToolIPv6ULA renders the IPv6 ULA generator page.
// GET /tools/ipv6-ula
func (h *Handler) ToolIPv6ULA(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.IPv6ULA(h.toolsData(r, "IPv6 ULA Generator")))
}

// ToolMACLookup renders the MAC address lookup page.
// GET /tools/mac-lookup
func (h *Handler) ToolMACLookup(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.MACLookup(h.toolsData(r, "MAC Address Lookup")))
}

// ToolMACGen renders the MAC address generator page.
// GET /tools/mac-gen
func (h *Handler) ToolMACGen(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.MACGenerator(h.toolsData(r, "MAC Address Generator")))
}

// --- Text & Dev ---

// ToolRegex renders the regex tester page.
// GET /tools/regex
func (h *Handler) ToolRegex(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.RegexTester(h.toolsData(r, "Regex Tester")))
}

// ToolTextDiff renders the text diff page.
// GET /tools/text-diff
func (h *Handler) ToolTextDiff(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.TextDiff(h.toolsData(r, "Text Diff")))
}

// ToolTextStats renders the text statistics page.
// GET /tools/text-stats
func (h *Handler) ToolTextStats(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.TextStats(h.toolsData(r, "Text Statistics")))
}

// ToolSlugify renders the URL slug generator page.
// GET /tools/slugify
func (h *Handler) ToolSlugify(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.SlugGenerator(h.toolsData(r, "URL Slug Generator")))
}

// ToolDockerCompose renders the Docker run-to-compose converter page.
// GET /tools/docker-compose
func (h *Handler) ToolDockerCompose(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.DockerCompose(h.toolsData(r, "Docker Run → Compose")))
}

// ToolChmod renders the chmod calculator page.
// GET /tools/chmod
func (h *Handler) ToolChmod(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.ChmodCalculator(h.toolsData(r, "Chmod Calculator")))
}

// ToolHTTPCodes renders the HTTP status codes reference page.
// GET /tools/http-codes
func (h *Handler) ToolHTTPCodes(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.HTTPCodes(h.toolsData(r, "HTTP Status Codes")))
}

// ToolMarkdown renders the markdown preview page.
// GET /tools/markdown
func (h *Handler) ToolMarkdown(w http.ResponseWriter, r *http.Request) {
	h.renderTempl(w, r, tools.MarkdownPreview(h.toolsData(r, "Markdown Preview")))
}

// ============================================================================
// Calendar Handler
// ============================================================================

// CalendarPage renders the calendar page with events, tasks, and notes.
// GET /calendar
func (h *Handler) CalendarPage(w http.ResponseWriter, r *http.Request) {
	calData := calendar.CalendarData{
		PageData: h.prepareTemplPageData(r, "Calendar", "calendar"),
	}
	h.renderTempl(w, r, calendar.Calendar(calData))
}
