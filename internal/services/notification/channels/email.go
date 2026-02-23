// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package channels provides notification channel implementations.
// Department L: Notifications
package channels

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// EmailChannel sends notifications via SMTP email.
type EmailChannel struct {
	config       EmailConfig
	htmlTemplate *template.Template
	textTemplate *template.Template
}

// EmailConfig holds email channel configuration.
type EmailConfig struct {
	// SMTP server settings
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`

	// TLS configuration
	UseTLS      bool `json:"use_tls"`       // Use STARTTLS
	UseSSL      bool `json:"use_ssl"`       // Use implicit TLS (port 465)
	SkipVerify  bool `json:"skip_verify"`   // Skip certificate verification
	
	// Sender settings
	FromAddress string `json:"from_address"`
	FromName    string `json:"from_name,omitempty"`
	ReplyTo     string `json:"reply_to,omitempty"`

	// Recipients
	ToAddresses  []string `json:"to_addresses"`
	CCAddresses  []string `json:"cc_addresses,omitempty"`
	BCCAddresses []string `json:"bcc_addresses,omitempty"`

	// Content settings
	SubjectPrefix string `json:"subject_prefix,omitempty"` // e.g., "[USULNET]"
	SendHTML      *bool  `json:"send_html,omitempty"`      // Send HTML emails

	// Timeout in seconds
	Timeout int `json:"timeout,omitempty"`
}

// NewEmailChannel creates a new email notification channel.
func NewEmailChannel(config EmailConfig) (*EmailChannel, error) {
	if config.Host == "" {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if config.Port == 0 {
		// Default ports based on TLS settings
		if config.UseSSL {
			config.Port = 465
		} else if config.UseTLS {
			config.Port = 587
		} else {
			config.Port = 25
		}
	}
	if config.FromAddress == "" {
		return nil, fmt.Errorf("from address is required")
	}
	if len(config.ToAddresses) == 0 {
		return nil, fmt.Errorf("at least one recipient is required")
	}

	// Set defaults
	if config.FromName == "" {
		config.FromName = "USULNET"
	}
	if config.SubjectPrefix == "" {
		config.SubjectPrefix = "[USULNET]"
	}
	if config.SendHTML == nil {
		sendHTML := true
		config.SendHTML = &sendHTML
	}
	if config.Timeout == 0 {
		config.Timeout = 30
	}

	channel := &EmailChannel{
		config: config,
	}

	// Parse templates
	if err := channel.initTemplates(); err != nil {
		return nil, fmt.Errorf("failed to init templates: %w", err)
	}

	return channel, nil
}

// Name returns the channel identifier.
func (e *EmailChannel) Name() string {
	return "email"
}

// IsConfigured returns true if the channel has valid configuration.
func (e *EmailChannel) IsConfigured() bool {
	return e.config.Host != "" && e.config.FromAddress != "" && len(e.config.ToAddresses) > 0
}

// Send delivers a notification via email.
func (e *EmailChannel) Send(ctx context.Context, msg RenderedMessage) error {
	// Build email content
	subject := e.buildSubject(msg)
	body, contentType, err := e.buildBody(msg)
	if err != nil {
		return fmt.Errorf("failed to build email body: %w", err)
	}

	// Build message
	emailMsg := e.buildMessage(subject, body, contentType)

	// Send email
	if err := e.sendMail(ctx, emailMsg); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// Test sends a test email to verify configuration.
func (e *EmailChannel) Test(ctx context.Context) error {
	testMsg := RenderedMessage{
		Title:     "USULNET Test Notification",
		Body:      "This is a test notification from USULNET to verify email configuration.",
		BodyPlain: "This is a test notification from USULNET to verify email configuration.",
		Priority:  PriorityNormal,
		Timestamp: time.Now(),
		Type:      TypeTestMessage,
		Color:     "#3B82F6",
	}

	return e.Send(ctx, testMsg)
}

// buildSubject creates the email subject line.
func (e *EmailChannel) buildSubject(msg RenderedMessage) string {
	priorityPrefix := ""
	if msg.Priority >= PriorityCritical {
		priorityPrefix = "[CRITICAL] "
	} else if msg.Priority >= PriorityHigh {
		priorityPrefix = "[IMPORTANT] "
	}

	return fmt.Sprintf("%s %s%s", e.config.SubjectPrefix, priorityPrefix, msg.Title)
}

// buildBody creates the email body (HTML or plain text).
func (e *EmailChannel) buildBody(msg RenderedMessage) (string, string, error) {
	if *e.config.SendHTML {
		var buf bytes.Buffer
		data := map[string]interface{}{
			"Title":     msg.Title,
			"Body":      template.HTML(msg.Body), // Allow HTML in body
			"Priority":  msg.Priority.String(),
			"Type":      string(msg.Type),
			"Category":  msg.Type.Category(),
			"Timestamp": msg.Timestamp.Format("2006-01-02 15:04:05 MST"),
			"Color":     msg.Color,
			"Data":      msg.Data,
		}

		if err := e.htmlTemplate.Execute(&buf, data); err != nil {
			return "", "", err
		}

		return buf.String(), "text/html; charset=UTF-8", nil
	}

	// Plain text fallback
	return msg.BodyPlain, "text/plain; charset=UTF-8", nil
}

// buildMessage creates the MIME message.
func (e *EmailChannel) buildMessage(subject, body, contentType string) []byte {
	var buf bytes.Buffer

	// Headers
	from := e.formatAddress(e.config.FromName, e.config.FromAddress)
	buf.WriteString(fmt.Sprintf("From: %s\r\n", from))
	buf.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(e.config.ToAddresses, ", ")))
	
	if len(e.config.CCAddresses) > 0 {
		buf.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(e.config.CCAddresses, ", ")))
	}
	
	if e.config.ReplyTo != "" {
		buf.WriteString(fmt.Sprintf("Reply-To: %s\r\n", e.config.ReplyTo))
	}

	// Encode subject for UTF-8
	encodedSubject := e.encodeSubject(subject)
	buf.WriteString(fmt.Sprintf("Subject: %s\r\n", encodedSubject))
	
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString(fmt.Sprintf("Content-Type: %s\r\n", contentType))
	buf.WriteString("Content-Transfer-Encoding: base64\r\n")
	buf.WriteString(fmt.Sprintf("Date: %s\r\n", time.Now().Format(time.RFC1123Z)))
	buf.WriteString("X-Mailer: USULNET\r\n")
	buf.WriteString("\r\n")

	// Base64 encoded body
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	// Wrap at 76 characters per line
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}

	return buf.Bytes()
}

// sendMail sends the email via SMTP.
func (e *EmailChannel) sendMail(ctx context.Context, message []byte) error {
	addr := fmt.Sprintf("%s:%d", e.config.Host, e.config.Port)

	// Collect all recipients
	recipients := make([]string, 0, len(e.config.ToAddresses)+len(e.config.CCAddresses)+len(e.config.BCCAddresses))
	recipients = append(recipients, e.config.ToAddresses...)
	recipients = append(recipients, e.config.CCAddresses...)
	recipients = append(recipients, e.config.BCCAddresses...)

	if e.config.SkipVerify {
		slog.Warn("SMTP TLS certificate verification is DISABLED — this is insecure outside development environments",
			"host", e.config.Host,
		)
	}

	tlsConfig := &tls.Config{
		ServerName:         e.config.Host,
		InsecureSkipVerify: e.config.SkipVerify, //nolint:gosec // User-configurable for self-signed SMTP servers
	}

	var conn net.Conn
	var err error

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: time.Duration(e.config.Timeout) * time.Second,
	}

	if e.config.UseSSL {
		// Implicit TLS (port 465)
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, e.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// STARTTLS if configured (and not using implicit TLS)
	if e.config.UseTLS && !e.config.UseSSL {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	// Authenticate if credentials provided
	if e.config.Username != "" && e.config.Password != "" {
		auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
	}

	// Set sender
	if err := client.Mail(e.config.FromAddress); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", rcpt, err)
		}
	}

	// Send message
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to open data: %w", err)
	}

	if _, err := w.Write(message); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to close data: %w", err)
	}

	return client.Quit()
}

// formatAddress formats a name/email pair.
func (e *EmailChannel) formatAddress(name, address string) string {
	if name == "" {
		return address
	}
	// Encode name if it contains non-ASCII
	if needsEncoding(name) {
		return fmt.Sprintf("=?UTF-8?B?%s?= <%s>", base64.StdEncoding.EncodeToString([]byte(name)), address)
	}
	return fmt.Sprintf("%s <%s>", name, address)
}

// encodeSubject encodes the subject for UTF-8 if needed.
func (e *EmailChannel) encodeSubject(subject string) string {
	if needsEncoding(subject) {
		return fmt.Sprintf("=?UTF-8?B?%s?=", base64.StdEncoding.EncodeToString([]byte(subject)))
	}
	return subject
}

// needsEncoding checks if a string contains non-ASCII characters.
func needsEncoding(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

// initTemplates initializes the HTML email template.
func (e *EmailChannel) initTemplates() error {
	htmlTmpl := `<!DOCTYPE html>
<html lang="en" xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="color-scheme" content="light dark">
    <meta name="supported-color-schemes" content="light dark">
    <title>{{.Title}}</title>
    <!--[if mso]><noscript><xml><o:OfficeDocumentSettings><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml></noscript><![endif]-->
    <style>
        :root { color-scheme: light dark; supported-color-schemes: light dark; }
        body { margin: 0; padding: 0; width: 100%; background-color: #0f1117; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale; }
        .outer-table { width: 100%; background-color: #0f1117; }
        .spacer { height: 32px; }
        .spacer-sm { height: 16px; }
        .container { max-width: 600px; margin: 0 auto; background-color: #1a1d27; border-radius: 12px; overflow: hidden; border: 1px solid #2a2d3a; }
        .brand-bar { background-color: #12141c; padding: 20px 28px; border-bottom: 1px solid #2a2d3a; }
        .brand-name { font-size: 15px; font-weight: 700; color: #818cf8; letter-spacing: 0.5px; text-decoration: none; }
        .brand-sep { color: #3f4255; margin: 0 10px; }
        .brand-label { font-size: 12px; font-weight: 500; color: #6b7280; text-transform: uppercase; letter-spacing: 0.8px; }
        .priority-strip { height: 4px; background: {{.Color}}; }
        .header { padding: 28px 28px 20px; }
        .header h1 { margin: 0 0 8px; font-size: 22px; font-weight: 700; color: #f1f5f9; line-height: 1.3; }
        .header-meta { font-size: 13px; color: #6b7280; }
        .header-meta .badge { display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; vertical-align: middle; }
        .badge-critical { background-color: #991b1b; color: #fecaca; }
        .badge-high { background-color: #92400e; color: #fde68a; }
        .badge-normal { background-color: #1e3a5f; color: #93c5fd; }
        .badge-low { background-color: #27272a; color: #a1a1aa; }
        .divider { border: none; border-top: 1px solid #2a2d3a; margin: 0 28px; }
        .content { padding: 24px 28px; color: #d1d5db; font-size: 14px; line-height: 1.7; }
        .content p { margin: 0 0 12px; }
        .content strong { color: #f1f5f9; font-weight: 600; }
        .content code { background-color: #12141c; color: #a5b4fc; padding: 2px 6px; border-radius: 4px; font-size: 13px; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; }
        .data-section { padding: 0 28px 24px; }
        .data-table { width: 100%; border-collapse: separate; border-spacing: 0; border-radius: 8px; overflow: hidden; border: 1px solid #2a2d3a; }
        .data-table th { padding: 10px 14px; text-align: left; background-color: #12141c; font-weight: 600; font-size: 11px; color: #818cf8; text-transform: uppercase; letter-spacing: 0.8px; border-bottom: 1px solid #2a2d3a; }
        .data-table td { padding: 10px 14px; font-size: 13px; border-bottom: 1px solid #1f2233; }
        .data-table td:first-child { color: #9ca3af; font-weight: 500; width: 40%; }
        .data-table td:last-child { color: #e5e7eb; font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace; font-size: 12px; }
        .data-table tr:last-child td { border-bottom: none; }
        .data-table tr:hover td { background-color: #1f2233; }
        .footer { padding: 20px 28px; border-top: 1px solid #2a2d3a; background-color: #12141c; text-align: center; }
        .footer-text { font-size: 11px; color: #4b5563; line-height: 1.6; margin: 0; }
        .footer-link { color: #818cf8; text-decoration: none; }
        @media (prefers-color-scheme: light) {
            body, .outer-table { background-color: #f1f5f9 !important; }
            .container { background-color: #ffffff !important; border-color: #e2e8f0 !important; }
            .brand-bar { background-color: #f8fafc !important; border-color: #e2e8f0 !important; }
            .brand-name { color: #6366f1 !important; }
            .brand-sep { color: #cbd5e1 !important; }
            .brand-label { color: #64748b !important; }
            .header h1 { color: #0f172a !important; }
            .header-meta { color: #64748b !important; }
            .badge-normal { background-color: #dbeafe !important; color: #1e40af !important; }
            .badge-low { background-color: #f1f5f9 !important; color: #475569 !important; }
            .divider { border-color: #e2e8f0 !important; }
            .content { color: #334155 !important; }
            .content strong { color: #0f172a !important; }
            .content code { background-color: #f1f5f9 !important; color: #4f46e5 !important; }
            .data-table { border-color: #e2e8f0 !important; }
            .data-table th { background-color: #f8fafc !important; color: #4f46e5 !important; border-color: #e2e8f0 !important; }
            .data-table td { border-color: #f1f5f9 !important; }
            .data-table td:first-child { color: #64748b !important; }
            .data-table td:last-child { color: #1e293b !important; }
            .data-table tr:hover td { background-color: #f8fafc !important; }
            .footer { background-color: #f8fafc !important; border-color: #e2e8f0 !important; }
            .footer-text { color: #94a3b8 !important; }
            .footer-link { color: #6366f1 !important; }
        }
    </style>
</head>
<body>
    <table role="presentation" class="outer-table" cellpadding="0" cellspacing="0">
        <tr><td class="spacer"></td></tr>
        <tr>
            <td align="center" style="padding: 0 16px;">
                <table role="presentation" class="container" cellpadding="0" cellspacing="0" width="600">
                    <!-- Brand Bar -->
                    <tr>
                        <td class="brand-bar">
                            <span class="brand-name">USULNET</span>
                            <span class="brand-sep">&middot;</span>
                            <span class="brand-label">{{.Category}}</span>
                        </td>
                    </tr>
                    <!-- Priority Color Strip -->
                    <tr><td class="priority-strip"></td></tr>
                    <!-- Header -->
                    <tr>
                        <td class="header">
                            <h1>{{.Title}}</h1>
                            <div class="header-meta">
                                <span class="badge badge-{{.Priority}}">{{.Priority}}</span>
                                <span style="margin-left: 8px;">{{.Timestamp}}</span>
                            </div>
                        </td>
                    </tr>
                    <!-- Divider -->
                    <tr><td><hr class="divider"></td></tr>
                    <!-- Content -->
                    <tr>
                        <td class="content">
                            {{.Body}}
                        </td>
                    </tr>
                    <!-- Data Table -->
                    {{if .Data}}
                    <tr>
                        <td class="data-section">
                            <table role="presentation" class="data-table" cellpadding="0" cellspacing="0">
                                <thead>
                                    <tr><th>Field</th><th>Value</th></tr>
                                </thead>
                                <tbody>
                                    {{range $key, $value := .Data}}
                                    <tr><td>{{$key}}</td><td>{{$value}}</td></tr>
                                    {{end}}
                                </tbody>
                            </table>
                        </td>
                    </tr>
                    {{end}}
                    <!-- Footer -->
                    <tr>
                        <td class="footer">
                            <p class="footer-text">
                                Sent by <a href="https://usulnet.com" class="footer-link">usulnet</a> Docker Management Platform<br>
                                You received this because alerts are enabled for this event type.
                            </p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr><td class="spacer"></td></tr>
    </table>
</body>
</html>`

	var err error
	e.htmlTemplate, err = template.New("email").Parse(htmlTmpl)
	if err != nil {
		return fmt.Errorf("parse email HTML template: %w", err)
	}

	return nil
}

// NewEmailChannelFromSettings creates an EmailChannel from generic settings map.
func NewEmailChannelFromSettings(settings map[string]interface{}) (*EmailChannel, error) {
	// Manual conversion to handle nested types
	config := EmailConfig{}

	if v, ok := settings["host"].(string); ok {
		config.Host = v
	}
	if v, ok := settings["port"].(float64); ok {
		config.Port = int(v)
	}
	if v, ok := settings["username"].(string); ok {
		config.Username = v
	}
	if v, ok := settings["password"].(string); ok {
		config.Password = v
	}
	if v, ok := settings["use_tls"].(bool); ok {
		config.UseTLS = v
	}
	if v, ok := settings["use_ssl"].(bool); ok {
		config.UseSSL = v
	}
	if v, ok := settings["skip_verify"].(bool); ok {
		config.SkipVerify = v
	}
	if v, ok := settings["from_address"].(string); ok {
		config.FromAddress = v
	}
	if v, ok := settings["from_name"].(string); ok {
		config.FromName = v
	}
	if v, ok := settings["reply_to"].(string); ok {
		config.ReplyTo = v
	}
	if v, ok := settings["to_addresses"].([]interface{}); ok {
		for _, addr := range v {
			if s, ok := addr.(string); ok {
				config.ToAddresses = append(config.ToAddresses, s)
			}
		}
	}
	if v, ok := settings["cc_addresses"].([]interface{}); ok {
		for _, addr := range v {
			if s, ok := addr.(string); ok {
				config.CCAddresses = append(config.CCAddresses, s)
			}
		}
	}
	if v, ok := settings["subject_prefix"].(string); ok {
		config.SubjectPrefix = v
	}
	if v, ok := settings["send_html"].(bool); ok {
		config.SendHTML = &v
	}
	if v, ok := settings["timeout"].(float64); ok {
		config.Timeout = int(v)
	}

	return NewEmailChannel(config)
}
