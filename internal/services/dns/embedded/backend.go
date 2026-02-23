// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package embedded implements the miekg/dns-based DNS server backend.
// It runs an authoritative DNS server in-process, serving zones loaded
// from PostgreSQL via the SyncBackend interface.
package embedded

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/fr4nsys/usulnet/internal/models"
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config holds embedded DNS server configuration.
type Config struct {
	// ListenAddr is the UDP/TCP address to listen on (default ":53").
	ListenAddr string
	// Forwarders are upstream DNS servers for recursive queries.
	Forwarders []string
}

// Backend implements dnssvc.SyncBackend using miekg/dns.
type Backend struct {
	cfg    Config
	logger *logger.Logger

	udpServer *mdns.Server
	tcpServer *mdns.Server

	mu    sync.RWMutex
	zones map[string]*zoneData // zone name (FQDN) → data

	startTime time.Time
	stats     serverStats
}

// zoneData holds the in-memory representation of a DNS zone.
type zoneData struct {
	zone    *models.DNSZone
	records []*models.DNSRecord
}

// serverStats tracks query statistics using atomics for lock-free access.
type serverStats struct {
	queriesTotal   atomic.Uint64
	queriesSuccess atomic.Uint64
	queriesFailed  atomic.Uint64
}

// New creates a new embedded DNS backend.
func New(cfg Config, log *logger.Logger) *Backend {
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":53"
	}
	return &Backend{
		cfg:    cfg,
		logger: log.Named("dns_embedded"),
		zones:  make(map[string]*zoneData),
	}
}

// Mode returns the backend identifier.
func (b *Backend) Mode() string { return "embedded" }

// Start launches the UDP and TCP DNS servers.
func (b *Backend) Start(ctx context.Context) error {
	mux := mdns.NewServeMux()
	mux.HandleFunc(".", b.handleQuery)

	b.udpServer = &mdns.Server{
		Addr:    b.cfg.ListenAddr,
		Net:     "udp",
		Handler: mux,
	}
	b.tcpServer = &mdns.Server{
		Addr:    b.cfg.ListenAddr,
		Net:     "tcp",
		Handler: mux,
	}

	b.startTime = time.Now()

	errCh := make(chan error, 2)

	go func() {
		b.logger.Info("starting DNS server (UDP)", "addr", b.cfg.ListenAddr)
		if err := b.udpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("udp: %w", err)
		}
	}()

	go func() {
		b.logger.Info("starting DNS server (TCP)", "addr", b.cfg.ListenAddr)
		if err := b.tcpServer.ListenAndServe(); err != nil {
			errCh <- fmt.Errorf("tcp: %w", err)
		}
	}()

	// Give servers a moment to start or fail
	select {
	case err := <-errCh:
		return fmt.Errorf("DNS server failed to start: %w", err)
	case <-time.After(200 * time.Millisecond):
		b.logger.Info("DNS server started", "addr", b.cfg.ListenAddr)
		return nil
	}
}

// Stop gracefully shuts down both DNS servers.
func (b *Backend) Stop() error {
	var errs []error
	if b.udpServer != nil {
		if err := b.udpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("udp shutdown: %w", err))
		}
	}
	if b.tcpServer != nil {
		if err := b.tcpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Errorf("tcp shutdown: %w", err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("DNS server shutdown errors: %v", errs)
	}
	b.logger.Info("DNS server stopped")
	return nil
}

// Healthy checks if the DNS server is responding.
func (b *Backend) Healthy(ctx context.Context) (bool, error) {
	c := new(mdns.Client)
	c.Net = "udp"
	c.Timeout = 2 * time.Second

	m := new(mdns.Msg)
	m.SetQuestion(".", mdns.TypeNS)

	addr := b.cfg.ListenAddr
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}

	_, _, err := c.ExchangeContext(ctx, m, addr)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// Stats returns server statistics.
func (b *Backend) Stats() dnssvc.ServerStats {
	return dnssvc.ServerStats{
		QueriesTotal:   b.stats.queriesTotal.Load(),
		QueriesSuccess: b.stats.queriesSuccess.Load(),
		QueriesFailed:  b.stats.queriesFailed.Load(),
		ZonesLoaded:    len(b.zones),
		Uptime:         int64(time.Since(b.startTime).Seconds()),
	}
}

// Sync replaces the in-memory zone data with new data from the database.
func (b *Backend) Sync(ctx context.Context, data *dnssvc.SyncData) error {
	newZones := make(map[string]*zoneData, len(data.Zones))

	for _, z := range data.Zones {
		name := mdns.Fqdn(z.Name)
		recs := data.Records[z.ID.String()]
		newZones[name] = &zoneData{
			zone:    z,
			records: recs,
		}
	}

	b.mu.Lock()
	b.zones = newZones
	b.mu.Unlock()

	b.logger.Info("DNS zones synced", "count", len(newZones))
	return nil
}

// handleQuery processes incoming DNS queries.
func (b *Backend) handleQuery(w mdns.ResponseWriter, r *mdns.Msg) {
	b.stats.queriesTotal.Add(1)

	msg := new(mdns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.Compress = true

	if len(r.Question) == 0 {
		msg.Rcode = mdns.RcodeFormatError
		b.stats.queriesFailed.Add(1)
		_ = w.WriteMsg(msg)
		return
	}

	q := r.Question[0]
	qname := strings.ToLower(q.Name)

	b.mu.RLock()
	zd := b.findZone(qname)
	b.mu.RUnlock()

	if zd == nil {
		// Not authoritative — try forwarding
		if len(b.cfg.Forwarders) > 0 {
			b.forward(w, r)
			return
		}
		msg.Rcode = mdns.RcodeRefused
		b.stats.queriesFailed.Add(1)
		_ = w.WriteMsg(msg)
		return
	}

	// Answer from zone data
	answered := false
	for _, rec := range zd.records {
		if !rec.Enabled {
			continue
		}
		recName := mdns.Fqdn(rec.Name)
		if !strings.EqualFold(recName, qname) {
			continue
		}
		rr := b.buildRR(rec, zd.zone)
		if rr != nil && rr.Header().Rrtype == q.Qtype {
			msg.Answer = append(msg.Answer, rr)
			answered = true
		}
	}

	// Add SOA to authority section if we're authoritative
	if !answered {
		soa := b.buildSOA(zd.zone)
		if soa != nil {
			msg.Ns = append(msg.Ns, soa)
		}
		msg.Rcode = mdns.RcodeNameError
		b.stats.queriesFailed.Add(1)
	} else {
		b.stats.queriesSuccess.Add(1)
	}

	_ = w.WriteMsg(msg)
}

// findZone finds the most specific zone for a query name.
func (b *Backend) findZone(qname string) *zoneData {
	// Walk up the label tree to find the matching zone
	name := qname
	for {
		if zd, ok := b.zones[name]; ok {
			return zd
		}
		// Strip the leftmost label
		idx := strings.Index(name, ".")
		if idx < 0 || idx+1 >= len(name) {
			break
		}
		name = name[idx+1:]
	}
	return nil
}

// buildRR converts a DNS record model to a miekg/dns RR.
func (b *Backend) buildRR(rec *models.DNSRecord, zone *models.DNSZone) mdns.RR {
	name := mdns.Fqdn(rec.Name)
	ttl := uint32(rec.TTL)

	switch rec.Type {
	case models.DNSRecordTypeA:
		ip := net.ParseIP(rec.Content)
		if ip == nil || ip.To4() == nil {
			return nil
		}
		return &mdns.A{
			Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeA, Class: mdns.ClassINET, Ttl: ttl},
			A:   ip.To4(),
		}

	case models.DNSRecordTypeAAAA:
		ip := net.ParseIP(rec.Content)
		if ip == nil || ip.To16() == nil {
			return nil
		}
		return &mdns.AAAA{
			Hdr:  mdns.RR_Header{Name: name, Rrtype: mdns.TypeAAAA, Class: mdns.ClassINET, Ttl: ttl},
			AAAA: ip.To16(),
		}

	case models.DNSRecordTypeCNAME:
		return &mdns.CNAME{
			Hdr:    mdns.RR_Header{Name: name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: ttl},
			Target: mdns.Fqdn(rec.Content),
		}

	case models.DNSRecordTypeMX:
		prio := uint16(10)
		if rec.Priority != nil {
			prio = uint16(*rec.Priority)
		}
		return &mdns.MX{
			Hdr:        mdns.RR_Header{Name: name, Rrtype: mdns.TypeMX, Class: mdns.ClassINET, Ttl: ttl},
			Preference: prio,
			Mx:         mdns.Fqdn(rec.Content),
		}

	case models.DNSRecordTypeTXT:
		return &mdns.TXT{
			Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeTXT, Class: mdns.ClassINET, Ttl: ttl},
			Txt: []string{rec.Content},
		}

	case models.DNSRecordTypeNS:
		return &mdns.NS{
			Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypeNS, Class: mdns.ClassINET, Ttl: ttl},
			Ns:  mdns.Fqdn(rec.Content),
		}

	case models.DNSRecordTypeSRV:
		prio := uint16(0)
		weight := uint16(0)
		port := uint16(0)
		if rec.Priority != nil {
			prio = uint16(*rec.Priority)
		}
		if rec.Weight != nil {
			weight = uint16(*rec.Weight)
		}
		if rec.Port != nil {
			port = uint16(*rec.Port)
		}
		return &mdns.SRV{
			Hdr:      mdns.RR_Header{Name: name, Rrtype: mdns.TypeSRV, Class: mdns.ClassINET, Ttl: ttl},
			Priority: prio,
			Weight:   weight,
			Port:     port,
			Target:   mdns.Fqdn(rec.Content),
		}

	case models.DNSRecordTypePTR:
		return &mdns.PTR{
			Hdr: mdns.RR_Header{Name: name, Rrtype: mdns.TypePTR, Class: mdns.ClassINET, Ttl: ttl},
			Ptr: mdns.Fqdn(rec.Content),
		}

	case models.DNSRecordTypeSOA:
		return b.buildSOA(zone)

	default:
		return nil
	}
}

// buildSOA generates a SOA record for a zone.
func (b *Backend) buildSOA(zone *models.DNSZone) *mdns.SOA {
	name := mdns.Fqdn(zone.Name)
	ns := zone.PrimaryNS
	if ns == "" {
		ns = "ns1." + zone.Name
	}
	email := zone.AdminEmail
	if email == "" {
		email = "admin." + zone.Name
	}
	// Convert email: user@domain → user.domain (DNS SOA format)
	email = strings.Replace(email, "@", ".", 1)

	return &mdns.SOA{
		Hdr:     mdns.RR_Header{Name: name, Rrtype: mdns.TypeSOA, Class: mdns.ClassINET, Ttl: uint32(zone.TTL)},
		Ns:      mdns.Fqdn(ns),
		Mbox:    mdns.Fqdn(email),
		Serial:  uint32(zone.Serial),
		Refresh: uint32(zone.Refresh),
		Retry:   uint32(zone.Retry),
		Expire:  uint32(zone.Expire),
		Minttl:  uint32(zone.MinimumTTL),
	}
}

// forward sends a query to upstream forwarders.
func (b *Backend) forward(w mdns.ResponseWriter, r *mdns.Msg) {
	c := new(mdns.Client)
	c.Timeout = 5 * time.Second

	// Determine protocol from writer
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		c.Net = "tcp"
	} else {
		c.Net = "udp"
	}

	for _, fwd := range b.cfg.Forwarders {
		// Ensure the forwarder address has a port
		if _, _, err := net.SplitHostPort(fwd); err != nil {
			fwd = net.JoinHostPort(fwd, "53")
		}

		resp, _, err := c.Exchange(r, fwd)
		if err != nil {
			b.logger.Debug("forwarder failed", "server", fwd, "error", err)
			continue
		}
		b.stats.queriesSuccess.Add(1)
		_ = w.WriteMsg(resp)
		return
	}

	// All forwarders failed
	msg := new(mdns.Msg)
	msg.SetReply(r)
	msg.Rcode = mdns.RcodeServerFailure
	b.stats.queriesFailed.Add(1)
	_ = w.WriteMsg(msg)
}
