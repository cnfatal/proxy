package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

// Sniffer defines the interface for domain sniffing
type Sniffer interface {
	Sniff(conn net.Conn) (string, []byte, error)
}

// domainSniffer implements the Sniffer interface
type domainSniffer struct {
	pool    BufferPool
	timeout time.Duration
}

// NewSniffer creates a new domain sniffer
func NewSniffer(pool BufferPool, timeout time.Duration) Sniffer {
	return &domainSniffer{
		pool:    pool,
		timeout: timeout,
	}
}

// PeekedConn wraps a net.Conn and allows replaying peeked data
type PeekedConn struct {
	net.Conn
	reader io.Reader
	peeked []byte
	pool   BufferPool
}

func NewPeekedConn(conn net.Conn, peeked []byte, pool BufferPool) *PeekedConn {
	return &PeekedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peeked), conn),
		peeked: peeked,
		pool:   pool,
	}
}

func (c *PeekedConn) Read(p []byte) (n int, err error) {
	return c.reader.Read(p)
}

func (c *PeekedConn) Close() error {
	if c.peeked != nil {
		c.pool.Put(c.peeked)
		c.peeked = nil
	}
	return c.Conn.Close()
}

func (c *PeekedConn) CloseWrite() error {
	if cw, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Sniff tries to identify the domain name from the initial bytes of a connection
func (s *domainSniffer) Sniff(conn net.Conn) (string, []byte, error) {
	if s.timeout > 0 {
		conn.SetReadDeadline(time.Now().Add(s.timeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	buf := s.pool.GetSmall()
	total := 0

	for total < SmallBufferSize {
		n, err := conn.Read(buf[total:SmallBufferSize])
		total += n

		if total <= 0 {
			if err != nil {
				s.pool.Put(buf)
				return "", nil, err
			}
			continue
		}

		peeked := buf[:total]
		switch {
		case peeked[0] == 0x16:
			if domain, done := sniffSNI(peeked); done {
				return domain, peeked, nil
			}
		case isLikelyHTTP(peeked):
			if domain, done := sniffHTTP(peeked); done {
				return domain, peeked, nil
			}
		default:
			return "", peeked, nil
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", peeked, nil
			}
			return "", peeked, err
		}
	}

	return "", buf[:total], nil
}

func sniffSNI(data []byte) (string, bool) {
	if len(data) < 5 {
		return "", false
	}
	if data[0] != 0x16 {
		return "", true
	}

	recordLen := int(data[3])<<8 | int(data[4])
	if len(data) < 5+recordLen {
		return "", false
	}
	data = data[5 : 5+recordLen]

	if len(data) < 4 || data[0] != 0x01 { // Handshake Type: Client Hello (1)
		return "", true
	}

	// Skip handshake header (4 bytes)
	data = data[4:]
	if len(data) < 34 { // Version (2) + Random (32)
		return "", true
	}
	data = data[34:]

	// Session ID
	if len(data) < 1 {
		return "", true
	}
	sessionIDLen := int(data[0])
	if len(data) < 1+sessionIDLen {
		return "", true
	}
	data = data[1+sessionIDLen:]

	// Cipher Suites
	if len(data) < 2 {
		return "", true
	}
	cipherSuiteLen := int(data[0])<<8 | int(data[1])
	if len(data) < 2+cipherSuiteLen {
		return "", true
	}
	data = data[2+cipherSuiteLen:]

	// Compression Methods
	if len(data) < 1 {
		return "", true
	}
	compressionMethodLen := int(data[0])
	if len(data) < 1+compressionMethodLen {
		return "", true
	}
	data = data[1+compressionMethodLen:]

	// Extensions
	if len(data) < 2 {
		return "", true
	}
	extensionsLen := int(data[0])<<8 | int(data[1])
	data = data[2:]
	if len(data) < extensionsLen {
		return "", true
	}

	for len(data) >= 4 {
		extType := int(data[0])<<8 | int(data[1])
		extLen := int(data[2])<<8 | int(data[3])
		data = data[4:]
		if len(data) < extLen {
			break
		}

		if extType == 0x00 { // Server Name Extension
			snData := data[:extLen]
			if len(snData) < 2 {
				return "", true
			}
			snListLen := int(snData[0])<<8 | int(snData[1])
			snData = snData[2:]
			if len(snData) < snListLen {
				return "", true
			}
			for len(snData) >= 3 {
				nameType := snData[0]
				nameLen := int(snData[1])<<8 | int(snData[2])
				snData = snData[3:]
				if len(snData) < nameLen {
					return "", true
				}
				if nameType == 0x00 { // Host Name
					return string(snData[:nameLen]), true
				}
				snData = snData[nameLen:]
			}
		}
		data = data[extLen:]
	}

	return "", true
}

func isLikelyHTTP(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	// Common HTTP methods: GET, POST, HEAD, PUT, DELETE, OPTIONS, TRACE, PATCH, CONNECT
	switch data[0] {
	case 'G', 'P', 'H', 'D', 'O', 'T', 'C':
		return true
	}
	return false
}

func sniffHTTP(data []byte) (string, bool) {
	if !bytes.Contains(data, []byte("\r\n\r\n")) && !bytes.Contains(data, []byte("\n\n")) {
		return "", false
	}

	// Find the end of the first line
	idx := bytes.IndexByte(data, '\n')
	if idx == -1 {
		return "", false
	}
	firstLine := data[:idx]

	// Check if it looks like an HTTP request: METHOD PATH HTTP/1.x
	parts := bytes.Split(firstLine, []byte(" "))
	if len(parts) < 3 {
		return "", true
	}
	if !bytes.HasPrefix(parts[len(parts)-1], []byte("HTTP/")) {
		return "", true
	}

	// Look for Host header in subsequent lines
	remaining := data[idx+1:]
	for len(remaining) > 0 {
		idx := bytes.IndexByte(remaining, '\n')
		var line []byte
		if idx == -1 {
			line = remaining
			remaining = nil
		} else {
			line = remaining[:idx]
			remaining = remaining[idx+1:]
		}

		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			break // End of headers
		}

		if bytes.HasPrefix(bytes.ToLower(line), []byte("host:")) {
			host := bytes.TrimSpace(line[5:])
			// Remove port if present
			hostStr := string(host)
			if h, _, err := net.SplitHostPort(hostStr); err == nil {
				return h, true
			}
			return hostStr, true
		}
	}

	return "", true
}
