package codesign

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const replyHeaders = "HTTP/1.1 200 OK\r\nContent-Type: application/timestamp-reply\r\n"

func TestTimestampHTTPResponseFraming(t *testing.T) {
	for _, response := range []string{
		replyHeaders + "Content-Length: 3\r\n\r\nabc",
		replyHeaders + "Content-Length: 0003\r\nContent-Encoding: identity\r\n\r\nabc",
		replyHeaders + "\r\nabc",
		"HTTP/1.0 200 \r\nContent-Type: application/timestamp-reply; version=1\r\n\r\nabc",
		replyHeaders + "Transfer-Encoding: Chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\nX-Ignored: yes\r\n\r\n",
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: ignored\r\n\r\n" + replyHeaders + "Content-Length: 3\r\n\r\nabc",
	} {
		body, err := readTimestampHTTP(bufio.NewReaderSize(strings.NewReader(response), 8192))
		if err != nil || string(body) != "abc" {
			t.Fatalf("response %q: %q %v", response, body, err)
		}
	}
	for name, response := range map[string]string{
		"status-short":       "HTTP/1.1 200\r\n\r\n",
		"version":            "HTTP/2.0 200 OK\r\n\r\n",
		"bad-code":           "HTTP/1.1 xxx OK\r\n\r\n",
		"code-range":         "HTTP/1.1 999 OK\r\n\r\n",
		"redirect":           "HTTP/1.1 302 Found\r\nLocation: http://other.invalid\r\n\r\n",
		"protocol-switch":    "HTTP/1.1 101 Switching Protocols\r\n\r\n",
		"framed-continue":    "HTTP/1.1 100 Continue\r\nContent-Length: 0\r\n\r\n",
		"chunked-continue":   "HTTP/1.1 100 Continue\r\nTransfer-Encoding: chunked\r\n\r\n",
		"continue-limit":     strings.Repeat("HTTP/1.1 100 Continue\r\n\r\n", 10),
		"missing-type":       "HTTP/1.1 200 OK\r\n\r\nabc",
		"wrong-type":         "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nabc",
		"encoding":           replyHeaders + "Content-Encoding: gzip\r\n\r\nabc",
		"transfer":           replyHeaders + "Transfer-Encoding: gzip, chunked\r\n\r\n",
		"ambiguous":          replyHeaders + "Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n",
		"duplicate":          replyHeaders + "Content-Length: 3\r\ncontent-length: 3\r\n\r\nabc",
		"folded":             replyHeaders + " folded: header\r\n\r\n",
		"space-before-colon": replyHeaders + "Bad : header\r\n\r\n",
		"no-colon":           replyHeaders + "invalid\r\n\r\n",
		"empty-name":         replyHeaders + ": value\r\n\r\n",
		"control":            replyHeaders + "X-Test: before\x00after\r\n\r\n",
		"bare-lf":            replyHeaders + "X-Test: value\n\n",
		"header-line-size":   replyHeaders + "X-Test: " + strings.Repeat("x", 8192) + "\r\n\r\n",
		"header-total-size":  replyHeaders + strings.Repeat("X-Test: "+strings.Repeat("x", 8000)+"\r\n", 5) + "\r\n",
		"header-count":       replyHeaders + strings.Repeat("X-Test: x\r\n", 128) + "\r\n",
		"length-sign":        replyHeaders + "Content-Length: +3\r\n\r\nabc",
		"length-list":        replyHeaders + "Content-Length: 3, 3\r\n\r\nabc",
		"length-empty":       replyHeaders + "Content-Length:\r\n\r\n",
		"length-overflow":    replyHeaders + "Content-Length: 999999999999999999999\r\n\r\n",
		"length-limit":       replyHeaders + "Content-Length: 1048577\r\n\r\n",
		"length-truncated":   replyHeaders + "Content-Length: 4\r\n\r\nabc",
		"close-limit":        replyHeaders + "\r\n" + strings.Repeat("x", maxTimestampSize+1),
	} {
		t.Run(name, func(t *testing.T) {
			if b, err := readTimestampHTTP(bufio.NewReaderSize(strings.NewReader(response), 8192)); err == nil || b != nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
	for name, chunks := range map[string]string{
		"missing":         "",
		"empty-size":      "\r\n",
		"extension":       "1;foo=bar\r\na\r\n0\r\n\r\n",
		"invalid-size":    "-1\r\n",
		"overflow":        "10000000000000000\r\n",
		"body-limit":      "100001\r\n",
		"short-body":      "3\r\na",
		"missing-end":     "1\r\na",
		"wrong-end":       "1\r\naXX",
		"bad-trailer":     "0\r\ninvalid\r\n\r\n",
		"framing-trailer": "0\r\nContent-Length: 1\r\n\r\n",
		"chunk-budget":    strings.Repeat("1\r\na\r\n", 11000),
		"ending-budget":   strings.Repeat("1\r\na\r\n", 6552) + "00001\r\na\r\n",
	} {
		t.Run("chunk/"+name, func(t *testing.T) {
			if b, err := readTimestampHTTP(bufio.NewReaderSize(strings.NewReader(replyHeaders+"Transfer-Encoding: chunked\r\n\r\n"+chunks), 8192)); err == nil || b != nil {
				t.Fatal("invalid chunks accepted")
			}
		})
	}
	r := bufio.NewReader(io.MultiReader(strings.NewReader(replyHeaders+"\r\n"), errorReader{}))
	if _, err := readTimestampHTTP(r); err == nil {
		t.Fatal("body read error swallowed")
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("read failure") }

func TestTimestampHTTPURL(t *testing.T) {
	for _, u := range []string{"", "https://example.test/tsa", "ftp://example.test", "http:", "http://user:secret@host/", "http://host/#fragment", "http://host/#", "http:opaque", "http://host:", "http://host:0", "http://host:65536", "http://host:-1", "http://host:abc", "http://[oops]/", "http://[fe80::1%25zone]/", "http://é.test/", "http://host/?bad=\t", "http://host/?q=é", "http://host/%zz", strings.Repeat("x", 8193), "http://2001:db8::1:80/"} {
		if _, err := NewHTTPTimestampExchange(u, 0); err == nil {
			t.Fatalf("URL accepted: %q", u)
		}
	}
	for _, u := range []string{AppleTimestampURL, "http://127.0.0.1/tsa?q=hello%20world", "http://[::1]:8000/", "http://localhost/é"} {
		if _, err := NewHTTPTimestampExchange(u, 0); err != nil {
			t.Fatal(u, err)
		}
	}
	if _, err := NewHTTPTimestampExchange(AppleTimestampURL, -time.Second); err == nil {
		t.Fatal("negative timeout")
	}
}

func TestTimestampHTTPExchange(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		if r.Method != "POST" || r.URL.RequestURI() != "/tsa?q=1" || r.Header.Get("Content-Type") != "application/timestamp-query" || r.Header.Get("Accept") != "application/timestamp-reply" || string(data) != "request" {
			t.Error("unexpected request", r.Method, r.URL, string(data))
		}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		w.WriteHeader(200)
		w.(http.Flusher).Flush() // Exercise a real chunked response.
		_, _ = w.Write([]byte("response"))
	}))
	defer server.Close()
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	exchange, err := NewHTTPTimestampExchange(server.URL+"/tsa?q=1", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	got, err := exchange(context.Background(), []byte("request"))
	if err != nil || string(got) != "response" {
		t.Fatal(string(got), err)
	}
	for _, bad := range [][]byte{nil, make([]byte, maxTimestampSize+1)} {
		if _, err := exchange(context.Background(), bad); err == nil {
			t.Fatal("request limit")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := exchange(ctx, []byte("request")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	server.Close()
	if _, err := exchange(context.Background(), []byte("request")); err == nil {
		t.Fatal("connection refusal")
	}
}

func TestTimestampHTTPCancellation(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(fmt.Sprint(timeout), func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.Copy(io.Discard, r.Body)
				close(entered)
				<-release
			}))
			defer server.Close()
			defer close(release)
			duration := 5 * time.Second
			if timeout {
				duration = 500 * time.Millisecond
			}
			exchange, err := NewHTTPTimestampExchange(server.URL, duration)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { _, err := exchange(ctx, []byte("request")); done <- err }()
			select {
			case <-entered:
			case err := <-done:
				t.Fatal("exchange ended before server received request", err)
			}
			if !timeout {
				cancel()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled response succeeded")
				}
				if !timeout && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("HTTP exchange did not cancel")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(timestampNetworkError(ctx, "write", io.EOF), context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if !errors.Is(timestampNetworkError(context.Background(), "write", io.EOF), io.EOF) {
		t.Fatal("I/O error lost")
	}
}

func TestTimestampHTTPAcquire(t *testing.T) {
	tsa := timestampIdentity(t, "p256", nil)
	signature := []byte("signature")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		var req struct {
			Version int
			Imprint timestampImprint
			Nonce   *big.Int
			CertReq bool
		}
		if err := decodeDER(request, &req); err != nil {
			t.Error(err)
			return
		}
		v := testTimestamp{tsa: tsa, hash: crypto.SHA256, v2: true, editInfo: func(info *timestampTSTInfo) { info.Nonce = req.Nonce }}
		w.Header().Set("Content-Type", "application/timestamp-reply")
		_, _ = w.Write(derSequence(derSequence([]byte{2, 1, 0}, derSequence(derWrap(12, []byte("Operation Okay")))), v.token(t, signature)))
	}))
	defer server.Close()
	exchange, err := NewHTTPTimestampExchange(server.URL, 0)
	if err != nil {
		t.Fatal(err)
	}
	token, err := AcquireTimestamp(context.Background(), signature, exchange, [][]byte{tsa.Certificates[2]}, certificateTime)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyTimestampToken(token, signature, [][]byte{tsa.Certificates[2]}, certificateTime); err != nil {
		t.Fatal(err)
	}
}

func TestAppleTimestampRootCopies(t *testing.T) {
	roots := AppleTimestampRoots()
	if len(roots) != 3 {
		t.Fatal("missing roots")
	}
	for _, der := range roots {
		c, err := parseCertificate(der)
		if err != nil || !appleAnchor([]*certificate{c}) {
			t.Fatal("unexpected root", err)
		}
	}
	roots[0][0] ^= 1
	if bytes.Equal(roots[0], AppleTimestampRoots()[0]) {
		t.Fatal("mutated shared root")
	}
}

func FuzzTimestampHTTP(f *testing.F) {
	f.Add([]byte(replyHeaders + "Content-Length: 3\r\n\r\nabc"))
	f.Add([]byte(replyHeaders + "Transfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxTimestampSize+timestampHeaderLimit {
			return
		}
		_, _ = readTimestampHTTP(bufio.NewReaderSize(bytes.NewReader(data), 8192))
	})
}

func TestTimestampHTTPClangFacts(t *testing.T) {
	data, err := os.ReadFile("../../spec/apple-timestamp-http.json")
	if err != nil {
		t.Fatal(err)
	}
	var facts struct {
		DefaultURL string `json:"default_url"`
		Targets    map[string]map[string]struct{ Literals, Messages []string }
	}
	if err := json.Unmarshal(data, &facts); err != nil {
		t.Fatal(err)
	}
	if facts.DefaultURL != AppleTimestampURL || len(facts.Targets) != 2 {
		t.Fatal("Apple endpoint or targets differ")
	}
	for target, methods := range facts.Targets {
		init, post := methods["initWithURLString:"], methods["post:"]
		if !slices.Contains(init.Literals, strconv.FormatFloat(TimestampHTTPTimeout.Seconds(), 'f', -1, 64)) || !slices.Contains(init.Messages, "initWithURL:cachePolicy:timeoutInterval:") {
			t.Fatal(target, "Apple timeout differs")
		}
		for _, literal := range []string{`"POST"`, `"application/timestamp-query"`, `"Content-Type"`} {
			if !slices.Contains(post.Literals, literal) {
				t.Fatal(target, "Apple request literal missing", literal)
			}
		}
	}
}
