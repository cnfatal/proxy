package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cnfatal/proxy/config"
	"github.com/miekg/dns"
)

func (tp *TransparentProxy) handleDNSUDP(ctx context.Context, srcAddr net.Addr, origDst *net.UDPAddr, data []byte) {
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return
	}

	w := &udpDNSWriter{
		conn:    tp.udpConn,
		srcAddr: srcAddr,
	}

	tp.handleDNSRequest(ctx, w, msg)
}

type udpDNSWriter struct {
	conn    *net.UDPConn
	srcAddr net.Addr
}

func (w *udpDNSWriter) LocalAddr() net.Addr  { return nil }
func (w *udpDNSWriter) RemoteAddr() net.Addr { return w.srcAddr }
func (w *udpDNSWriter) WriteMsg(m *dns.Msg) error {
	data, err := m.Pack()
	if err != nil {
		return err
	}
	_, err = w.conn.WriteTo(data, w.srcAddr)
	return err
}

func (w *udpDNSWriter) Write(b []byte) (int, error) {
	return w.conn.WriteTo(b, w.srcAddr)
}
func (w *udpDNSWriter) Close() error        { return nil }
func (w *udpDNSWriter) TsigStatus() error   { return nil }
func (w *udpDNSWriter) TsigTimersOnly(bool) {}
func (w *udpDNSWriter) Hijack()             {}

func (tp *TransparentProxy) handleDNSTCP(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	dnsConn := &dns.Conn{Conn: conn}
	for {
		msg, err := dnsConn.ReadMsg()
		if err != nil {
			return
		}
		w := &tcpDNSWriter{conn: dnsConn}
		tp.handleDNSRequest(ctx, w, msg)
	}
}

type tcpDNSWriter struct {
	conn *dns.Conn
}

func (w *tcpDNSWriter) LocalAddr() net.Addr  { return w.conn.LocalAddr() }
func (w *tcpDNSWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }
func (w *tcpDNSWriter) WriteMsg(m *dns.Msg) error {
	return w.conn.WriteMsg(m)
}

func (w *tcpDNSWriter) Write(b []byte) (int, error) {
	return w.conn.Write(b)
}
func (w *tcpDNSWriter) Close() error        { return w.conn.Close() }
func (w *tcpDNSWriter) TsigStatus() error   { return nil }
func (w *tcpDNSWriter) TsigTimersOnly(bool) {}
func (w *tcpDNSWriter) Hijack()             {}

func (tp *TransparentProxy) handleDNSRequest(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")
	slog.Debug("DNS request", "query", q.Name, "type", dns.TypeToString[q.Qtype])

	// 1. Check custom DNS rules (prefix, suffix, etc.)
	for _, rule := range tp.dnsConfig.Rules {
		parts := strings.Split(rule, ",")
		if len(parts) != 2 {
			continue
		}
		pattern := parts[0]
		policy := strings.ToUpper(parts[1])

		matched := false
		if after, ok := strings.CutPrefix(pattern, "prefix:"); ok {
			if strings.HasPrefix(domain, after) {
				matched = true
			}
		} else if after, ok := strings.CutPrefix(pattern, "suffix:"); ok {
			if strings.HasSuffix(domain, after) {
				matched = true
			}
		} else if after0, ok0 := strings.CutPrefix(pattern, "keyword:"); ok0 {
			if strings.Contains(domain, after0) {
				matched = true
			}
		}

		if matched {
			switch policy {
			case "DIRECT":
				tp.resolveDirect(ctx, w, r)
				return
			case "PROXY":
				tp.resolveProxy(ctx, w, r)
				return
			}
		}
	}

	// 2. Check main rule matcher
	result := tp.matcher.Match(domain, nil)
	if result.Policy == config.PolicyProxy {
		tp.resolveProxy(ctx, w, r)
	} else {
		tp.resolveDirect(ctx, w, r)
	}
}

func (tp *TransparentProxy) resolveDirect(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if len(tp.dnsConfig.LocalNameservers) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	var reply *dns.Msg
	var err error
	for _, ns := range tp.dnsConfig.LocalNameservers {
		reply, err = tp.exchangeDNSDirect(ctx, r, ns)
		if err == nil {
			break
		}
	}

	if err != nil {
		slog.Error("DNS direct resolve failed", "query", r.Question[0].Name, "error", err)
		dns.HandleFailed(w, r)
		return
	}

	if reply != nil {
		reply.Id = r.Id
		w.WriteMsg(reply)
	}
}

func (tp *TransparentProxy) resolveProxy(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) {
	if len(tp.dnsConfig.Nameservers) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	var reply *dns.Msg
	var err error
	for _, ns := range tp.dnsConfig.Nameservers {
		reply, err = tp.exchangeDNSProxy(ctx, r, ns)
		if err == nil {
			break
		}
	}

	if err != nil {
		slog.Error("DNS proxy resolve failed", "query", r.Question[0].Name, "error", err)
		dns.HandleFailed(w, r)
		return
	}

	if reply != nil {
		reply.Id = r.Id
		w.WriteMsg(reply)
	}
}

func (tp *TransparentProxy) exchangeDNSDirect(ctx context.Context, m *dns.Msg, ns string) (*dns.Msg, error) {
	if _, _, err := net.SplitHostPort(ns); err != nil {
		ns = net.JoinHostPort(ns, "53")
	}
	client := &dns.Client{
		Net:     "udp",
		Timeout: 2 * time.Second,
		Dialer:  newBypassDialer(),
	}
	// dns.Client doesn't support DialContext directly in Exchange, but we can use ExchangeContext if available
	// miekg/dns supports ExchangeContext
	reply, _, err := client.ExchangeContext(ctx, m, ns)
	return reply, err
}

func (tp *TransparentProxy) exchangeDNSProxy(ctx context.Context, m *dns.Msg, ns string) (*dns.Msg, error) {
	if _, _, err := net.SplitHostPort(ns); err != nil {
		ns = net.JoinHostPort(ns, "53")
	}

	if tp.upstream == nil {
		return nil, fmt.Errorf("no upstream proxy configured for DNS resolution")
	}

	conn, err := tp.upstream.Connect(ctx, ns)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	return dns.ExchangeConn(conn, m)
}
