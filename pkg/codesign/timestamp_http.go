package codesign

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// AppleTimestampURL is the endpoint in Apple's published TimeStampingPrefs.plist.
const AppleTimestampURL = "http://timestamp.apple.com/ts01"

// TimestampHTTPTimeout matches Apple's published timestamp request timeout.
const TimestampHTTPTimeout = 15 * time.Second

const timestampHeaderLimit = 32 << 10

// NewHTTPTimestampExchange creates a bounded, direct HTTP/1.x POST exchange.
// Zero timeout selects TimestampHTTPTimeout. It uses Go's DNS resolver and no
// platform trust, HTTP/TLS package, proxy environment, redirects or retries.
// Response authentication belongs to AcquireTimestamp, not to this transport.
// HTTPS, URL credentials/fragments, compression and transfer codings other than
// chunked are rejected. Each exchange closes its connection after one response.
func NewHTTPTimestampExchange(serverURL string, timeout time.Duration) (TimestampExchange, error) {
	if len(serverURL) > 8192 {
		return nil, malformed("timestamp URL length")
	}
	u, err := url.Parse(serverURL)
	if err != nil {
		return nil, malformed("timestamp URL")
	}
	if u.Scheme != "http" {
		return nil, unsupported("only HTTP timestamp URLs are supported")
	}
	if u.Host == "" || u.User != nil || u.Opaque != "" || strings.Contains(serverURL, "#") {
		return nil, malformed("timestamp URL host, credentials or fragment")
	}
	host := u.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return nil, malformed("timestamp host")
	}
	for _, c := range u.Host {
		if c <= 32 || c >= 127 {
			return nil, malformed("timestamp host encoding")
		}
	}
	if strings.Contains(host, ":") && (!strings.HasPrefix(u.Host, "[") || net.ParseIP(host) == nil) || strings.HasPrefix(u.Host, "[") && net.ParseIP(host) == nil {
		return nil, malformed("timestamp IP address")
	}
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return nil, malformed("timestamp port")
		}
		port = "80"
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return nil, malformed("timestamp port")
	}
	uri := u.RequestURI()
	for _, c := range uri {
		if c <= 32 || c >= 127 {
			return nil, malformed("timestamp request URI encoding")
		}
	}
	if timeout < 0 {
		return nil, malformed("negative timestamp timeout")
	}
	if timeout == 0 {
		timeout = TimestampHTTPTimeout
	}
	address := net.JoinHostPort(host, port)
	return func(ctx context.Context, request []byte) ([]byte, error) {
		if len(request) == 0 || len(request) > maxTimestampSize {
			return nil, malformed("timestamp HTTP request size")
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		dialer := net.Dialer{Resolver: &net.Resolver{PreferGo: true}}
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err != nil {
			return nil, fmt.Errorf("timestamp HTTP connect: %w", err)
		}
		defer conn.Close()
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		deadline, _ := ctx.Deadline()
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("timestamp HTTP deadline: %w", err)
		}
		// URL components have been validated; no caller-supplied header text is accepted.
		header := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/timestamp-query\r\nAccept: application/timestamp-reply\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", uri, u.Host, len(request))
		if _, err := io.Copy(conn, io.MultiReader(strings.NewReader(header), bytes.NewReader(request))); err != nil {
			return nil, timestampNetworkError(ctx, "write", err)
		}
		response, err := readTimestampHTTP(bufio.NewReaderSize(conn, 8192))
		if err != nil {
			return nil, timestampNetworkError(ctx, "response", err)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return response, nil
	}, nil
}

func timestampNetworkError(ctx context.Context, stage string, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return fmt.Errorf("timestamp HTTP %s: %w", stage, err)
}

func timestampHTTPLine(r *bufio.Reader, budget *int) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", fmt.Errorf("timestamp HTTP line: %w", err)
	}
	*budget -= len(line)
	if *budget < 0 || len(line) < 2 || line[len(line)-2] != '\r' {
		return "", malformed("timestamp HTTP header limit or line ending")
	}
	line = line[:len(line)-2]
	for _, c := range line {
		if c == 127 || c < 32 && c != '\t' {
			return "", malformed("timestamp HTTP control character")
		}
	}
	return string(line), nil
}

func timestampHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", c) {
			return false
		}
	}
	return true
}

func timestampHTTPHeaders(r *bufio.Reader, budget *int) (map[string]string, error) {
	headers := map[string]string{}
	for count := 0; count < 128; count++ {
		line, err := timestampHTTPLine(r, budget)
		if err != nil {
			return nil, err
		}
		if line == "" {
			return headers, nil
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok || !timestampHeaderName(name) {
			return nil, malformed("timestamp HTTP header name or folding")
		}
		name = strings.ToLower(name)
		switch name {
		case "content-length", "transfer-encoding", "content-type", "content-encoding":
			if _, duplicate := headers[name]; duplicate {
				return nil, malformed("duplicate timestamp HTTP %s", name)
			}
			headers[name] = strings.Trim(value, " \t")
		}
	}
	return nil, malformed("timestamp HTTP header count")
}

func readTimestampHTTP(r *bufio.Reader) ([]byte, error) {
	budget := timestampHeaderLimit
	var headers map[string]string
	for interim := 0; ; interim++ {
		if interim > 8 {
			return nil, malformed("timestamp HTTP informational response limit")
		}
		line, err := timestampHTTPLine(r, &budget)
		if err != nil {
			return nil, err
		}
		if len(line) < 13 || line[:9] != "HTTP/1.1 " && line[:9] != "HTTP/1.0 " || line[12] != ' ' {
			return nil, malformed("timestamp HTTP status line")
		}
		status, err := strconv.Atoi(line[9:12])
		if err != nil || status < 100 || status > 599 {
			return nil, malformed("timestamp HTTP status code")
		}
		headers, err = timestampHTTPHeaders(r, &budget)
		if err != nil {
			return nil, err
		}
		if status == 100 || status == 102 || status == 103 {
			if _, ok := headers["content-length"]; ok {
				return nil, malformed("framed informational timestamp response")
			}
			if _, ok := headers["transfer-encoding"]; ok {
				return nil, malformed("framed informational timestamp response")
			}
			continue
		}
		if status != 200 {
			return nil, invalid("timestamp HTTP status %d", status)
		}
		break
	}
	media, _, err := mime.ParseMediaType(headers["content-type"])
	if err != nil || media != "application/timestamp-reply" {
		return nil, invalid("timestamp HTTP Content-Type must be application/timestamp-reply")
	}
	if value, ok := headers["content-encoding"]; ok && !strings.EqualFold(value, "identity") {
		return nil, unsupported("compressed timestamp HTTP response")
	}
	te, hasTE := headers["transfer-encoding"]
	cl, hasCL := headers["content-length"]
	if hasTE {
		if hasCL {
			return nil, malformed("ambiguous timestamp HTTP framing")
		}
		if !strings.EqualFold(te, "chunked") {
			return nil, unsupported("timestamp HTTP transfer coding")
		}
		return readTimestampChunks(r)
	}
	if hasCL {
		if cl == "" || strings.IndexFunc(cl, func(c rune) bool { return c < '0' || c > '9' }) >= 0 {
			return nil, malformed("timestamp HTTP Content-Length")
		}
		length, err := strconv.ParseUint(cl, 10, 32)
		if err != nil || length > maxTimestampSize {
			return nil, malformed("timestamp HTTP response size")
		}
		body := make([]byte, int(length))
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return body, nil
	}
	body, err := io.ReadAll(io.LimitReader(r, maxTimestampSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxTimestampSize {
		return nil, malformed("timestamp HTTP response size")
	}
	return body, nil
}

func readTimestampChunks(r *bufio.Reader) ([]byte, error) {
	// Bound framing overhead as well as payload bytes, including trailers.
	budget := timestampHeaderLimit
	var body []byte
	for {
		line, err := timestampHTTPLine(r, &budget)
		if err != nil {
			return nil, err
		}
		// This bounded profile rejects chunk extensions rather than parsing a
		// second quoted-string grammar that the Apple TSA does not require.
		if line == "" || strings.IndexFunc(line, func(c rune) bool { return (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') }) >= 0 {
			return nil, malformed("timestamp HTTP chunk size or extension")
		}
		n, err := strconv.ParseUint(line, 16, 32)
		if err != nil || n > uint64(maxTimestampSize-len(body)) {
			return nil, malformed("timestamp HTTP chunk body limit")
		}
		if n == 0 {
			trailers, err := timestampHTTPHeaders(r, &budget)
			if err != nil {
				return nil, err
			}
			if len(trailers) != 0 {
				return nil, malformed("timestamp HTTP framing or representation trailer")
			}
			return body, nil
		}
		start := len(body)
		body = append(body, make([]byte, int(n))...)
		if _, err := io.ReadFull(r, body[start:]); err != nil {
			return nil, err
		}
		var crlf [2]byte
		budget -= 2
		if budget < 0 {
			return nil, malformed("timestamp HTTP chunk framing limit")
		}
		if _, err := io.ReadFull(r, crlf[:]); err != nil {
			return nil, err
		}
		if crlf != [2]byte{'\r', '\n'} {
			return nil, malformed("timestamp HTTP chunk ending")
		}
	}
}
