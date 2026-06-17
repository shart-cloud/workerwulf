package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"
	"golang.org/x/crypto/acme/autocert"
)

type config struct {
	CallbackDomain string
	DNSZone        string
	NameserverHost string
	LogDir         string
	R2Bucket       string
	R2Endpoint     string
	R2AccessKey    string
	R2SecretKey    string
	R2AccountID    string
	DNSAnswerIPv4  string
	AutocertDir    string
	UploadTimeout  time.Duration
	BodyLimitBytes int64
	TLSHosts       []string
}

type server struct {
	cfg      config
	sink     *sink
	upgrader websocket.Upgrader
	dnsA     net.IP
	dnsZone  string
	soaNS    string
}

type sink struct {
	logDir   string
	uploader uploader
	mu       sync.Mutex
	files    map[string]*os.File
}

type uploader interface {
	Upload(ctx context.Context, event eventEnvelope) error
}

type noopUploader struct{}

type r2Uploader struct {
	bucket  string
	client  *s3.Client
	timeout time.Duration
}

type eventEnvelope struct {
	ID        string         `json:"id"`
	Timestamp string         `json:"timestamp"`
	Type      string         `json:"type"`
	Fields    map[string]any `json:"fields"`
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.LUTC)

	cfg := mustLoadConfig()
	s, err := newServer(cfg)
	if err != nil {
		log.Fatalf("init server: %v", err)
	}

	go func() {
		if err := s.serveDNSUDP(); err != nil {
			log.Fatalf("dns udp: %v", err)
		}
	}()
	go func() {
		if err := s.serveDNSTCP(); err != nil {
			log.Fatalf("dns tcp: %v", err)
		}
	}()
	go func() {
		if err := s.serveHTTP(); err != nil {
			log.Fatalf("http: %v", err)
		}
	}()

	if err := s.serveHTTPS(); err != nil {
		log.Fatalf("https: %v", err)
	}
}

func mustLoadConfig() config {
	cfg := config{
		CallbackDomain: mustEnv("WULF_CALLBACK_DOMAIN"),
		DNSZone:        mustEnv("WULF_DNS_ZONE"),
		NameserverHost: envOr("WULF_NAMESERVER_HOST", ""),
		LogDir:         envOr("WULF_LOG_DIR", "/var/log/wulf"),
		R2Bucket:       envOr("WULF_R2_BUCKET", ""),
		R2Endpoint:     envOr("WULF_R2_ENDPOINT", ""),
		R2AccessKey:    envOr("WULF_R2_ACCESS_KEY_ID", ""),
		R2SecretKey:    envOr("WULF_R2_SECRET_ACCESS_KEY", ""),
		R2AccountID:    envOr("WULF_R2_ACCOUNT_ID", ""),
		DNSAnswerIPv4:  mustEnv("WULF_DNS_ANSWER_IPV4"),
		AutocertDir:    envOr("WULF_AUTOCERT_DIR", "/var/lib/wulf/autocert"),
		UploadTimeout:  durationOr("WULF_UPLOAD_TIMEOUT", 10*time.Second),
		BodyLimitBytes: int64Or("WULF_BODY_LIMIT_BYTES", 1<<20),
	}

	if cfg.NameserverHost == "" {
		cfg.NameserverHost = "ns." + cfg.CallbackDomain
	}
	if cfg.R2Endpoint == "" && cfg.R2AccountID != "" {
		cfg.R2Endpoint = fmt.Sprintf("https://%s.r2.cloudflarestorage.com", cfg.R2AccountID)
	}
	cfg.CallbackDomain = strings.TrimSuffix(strings.ToLower(cfg.CallbackDomain), ".")
	cfg.DNSZone = strings.TrimSuffix(strings.ToLower(cfg.DNSZone), ".")
	cfg.NameserverHost = ensureFQDN(strings.ToLower(cfg.NameserverHost))
	cfg.TLSHosts = []string{cfg.CallbackDomain}
	return cfg
}

func newServer(cfg config) (*server, error) {
	dnsA := net.ParseIP(cfg.DNSAnswerIPv4).To4()
	if dnsA == nil {
		return nil, fmt.Errorf("WULF_DNS_ANSWER_IPV4 must be a valid IPv4 address")
	}
	uploader, err := newUploader(cfg)
	if err != nil {
		return nil, err
	}
	sink, err := newSink(cfg.LogDir, uploader)
	if err != nil {
		return nil, err
	}
	return &server{
		cfg:      cfg,
		sink:     sink,
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		dnsA:     dnsA,
		dnsZone:  ensureFQDN(cfg.DNSZone),
		soaNS:    cfg.NameserverHost,
	}, nil

}

func newSink(logDir string, uploader uploader) (*sink, error) {
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	return &sink{logDir: logDir, uploader: uploader, files: map[string]*os.File{}}, nil
}

func newUploader(cfg config) (uploader, error) {
	if cfg.R2Bucket == "" {
		log.Printf("r2 upload disabled: WULF_R2_BUCKET unset")
		return noopUploader{}, nil
	}
	if cfg.R2Endpoint == "" || cfg.R2AccessKey == "" || cfg.R2SecretKey == "" {
		return nil, fmt.Errorf("R2 upload enabled but endpoint/access key/secret key missing")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(
		context.Background(),
		awsconfig.WithRegion("auto"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.R2AccessKey, cfg.R2SecretKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(cfg.R2Endpoint)
		o.UsePathStyle = true
	})
	return &r2Uploader{bucket: cfg.R2Bucket, client: client, timeout: cfg.UploadTimeout}, nil
}

func (s *server) serveHTTP() error {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(s.cfg.AutocertDir),
		HostPolicy: autocert.HostWhitelist(s.cfg.TLSHosts...),
	}
	server := &http.Server{
		Addr:              ":80",
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           manager.HTTPHandler(s.httpMux()),
	}
	return server.ListenAndServe()
}

func (s *server) serveHTTPS() error {
	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(s.cfg.AutocertDir),
		HostPolicy: autocert.HostWhitelist(s.cfg.TLSHosts...),
	}
	server := &http.Server{
		Addr:              ":443",
		ReadHeaderTimeout: 5 * time.Second,
		Handler:           s.httpMux(),
		TLSConfig: &tls.Config{
			GetCertificate: manager.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
	}
	ln, err := net.Listen("tcp", server.Addr)
	if err != nil {
		return err
	}
	return server.ServeTLS(ln, "", "")
}

func (s *server) httpMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/ws", s.handleWS)
	mux.HandleFunc("/check", s.handleCheck)
	mux.HandleFunc("/config/", s.handleConfig)
	mux.HandleFunc("/", s.handleHTTP)
	return mux
}

type checkRequest struct {
	Path      string `json:"path"`
	Since     string `json:"since"`
	TestID    string `json:"test_id"`
	RunID     string `json:"run_id"`
	EventType string `json:"type"`
}

func (s *server) handleCheck(w http.ResponseWriter, r *http.Request) {
	pathFilter := r.URL.Query().Get("path")
	sinceStr := r.URL.Query().Get("since")
	testID := r.URL.Query().Get("test_id")
	runID := r.URL.Query().Get("run_id")

	httpPath := filepath.Join(s.cfg.LogDir, "http.jsonl")

	var since time.Time
	if sinceStr != "" {
		since, _ = time.Parse(time.RFC3339, sinceStr)
	}

	var matched []eventEnvelope
	f, err := os.Open(httpPath)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"found": false, "events": []eventEnvelope{}})
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var ev eventEnvelope
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}

		ts, _ := time.Parse(time.RFC3339Nano, ev.Timestamp)
		if !since.IsZero() && ts.Before(since) {
			continue
		}

		fields := ev.Fields
		if pathFilter != "" {
			p, _ := fields["path"].(string)
			if p != pathFilter {
				continue
			}
		}

		if testID != "" {
			rawQuery, _ := fields["query"].(string)
			q, _ := url.ParseQuery(rawQuery)
			if q.Get("test_id") != testID {
				continue
			}
		}

		if runID != "" {
			rawQuery, _ := fields["query"].(string)
			q, _ := url.ParseQuery(rawQuery)
			if q.Get("run_id") != runID {
				continue
			}
		}

		matched = append(matched, ev)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"found":  len(matched) > 0,
		"count":  len(matched),
		"events": matched,
	})
}

func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"theme":        "dark",
		"version":      "1.0.0",
		"monitoring":   true,
		"analytics_id": "UA-CONFIG-CANARY",
	})
}

func (s *server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(r.Body, s.cfg.BodyLimitBytes))
	event := eventEnvelope{
		ID:        newID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      "http",
		Fields: map[string]any{
			"scheme":         schemeOf(r),
			"method":         r.Method,
			"host":           r.Host,
			"path":           r.URL.Path,
			"query":          r.URL.RawQuery,
			"remote_addr":    r.RemoteAddr,
			"headers":        headerMap(r.Header),
			"content_length": r.ContentLength,
			"body_base64":    base64.StdEncoding.EncodeToString(body),
		},
	}
	if err := s.sink.Write(r.Context(), event); err != nil {
		log.Printf("write http event: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "event_id": event.ID})
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("websocket upgrade: %v", err)
		return
	}
	defer conn.Close()

	openEvent := eventEnvelope{
		ID:        newID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      "ws_open",
		Fields: map[string]any{
			"scheme":      schemeOf(r),
			"host":        r.Host,
			"path":        r.URL.Path,
			"query":       r.URL.RawQuery,
			"remote_addr": r.RemoteAddr,
			"headers":     headerMap(r.Header),
		},
	}
	if err := s.sink.Write(r.Context(), openEvent); err != nil {
		log.Printf("write ws open event: %v", err)
	}

	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("websocket read: %v", err)
			}
			closeEvent := eventEnvelope{
				ID:        newID(),
				Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
				Type:      "ws_close",
				Fields: map[string]any{
					"session_id": openEvent.ID,
					"error":      errString(err),
				},
			}
			if sinkErr := s.sink.Write(r.Context(), closeEvent); sinkErr != nil {
				log.Printf("write ws close event: %v", sinkErr)
			}
			return
		}
		msgEvent := eventEnvelope{
			ID:        newID(),
			Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
			Type:      "ws_message",
			Fields: map[string]any{
				"session_id":     openEvent.ID,
				"message_type":   msgType,
				"payload_base64": base64.StdEncoding.EncodeToString(payload),
			},
		}
		if err := s.sink.Write(r.Context(), msgEvent); err != nil {
			log.Printf("write ws message event: %v", err)
		}
		if err := conn.WriteMessage(msgType, payload); err != nil {
			log.Printf("websocket write: %v", err)
			return
		}
	}
}

func (s *server) serveDNSUDP() error {
	server := &dns.Server{Addr: ":53", Net: "udp", Handler: dns.HandlerFunc(s.handleDNS)}
	return server.ListenAndServe()
}

func (s *server) serveDNSTCP() error {
	server := &dns.Server{Addr: ":53", Net: "tcp", Handler: dns.HandlerFunc(s.handleDNS)}
	return server.ListenAndServe()
}

func (s *server) handleDNS(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	transport := "udp"
	if _, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		transport = "tcp"
	}

	questions := make([]map[string]any, 0, len(req.Question))
	for _, q := range req.Question {
		questions = append(questions, map[string]any{
			"name":   strings.ToLower(q.Name),
			"qtype":  dns.TypeToString[q.Qtype],
			"qclass": dns.ClassToString[q.Qclass],
		})
		s.addDNSAnswers(msg, q)
	}

	event := eventEnvelope{
		ID:        newID(),
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Type:      "dns",
		Fields: map[string]any{
			"remote_addr": w.RemoteAddr().String(),
			"transport":   transport,
			"opcode":      dns.OpcodeToString[req.Opcode],
			"questions":   questions,
		},
	}
	if err := s.sink.Write(context.Background(), event); err != nil {
		log.Printf("write dns event: %v", err)
	}

	if err := w.WriteMsg(msg); err != nil {
		log.Printf("dns write msg: %v", err)
	}
}

func (s *server) addDNSAnswers(msg *dns.Msg, q dns.Question) {
	name := strings.ToLower(q.Name)
	if !dns.IsSubDomain(s.dnsZone, name) {
		msg.Rcode = dns.RcodeNameError
		msg.Ns = append(msg.Ns, s.soaRecord())
		return
	}

	switch q.Qtype {
	case dns.TypeNS:
		if name == s.dnsZone {
			msg.Answer = append(msg.Answer, &dns.NS{Hdr: dns.RR_Header{Name: s.dnsZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: s.soaNS})
			return
		}
	case dns.TypeSOA:
		if name == s.dnsZone {
			msg.Answer = append(msg.Answer, s.soaRecord())
			return
		}
	case dns.TypeA:
		msg.Answer = append(msg.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: s.dnsA})
		return
	case dns.TypeTXT:
		msg.Answer = append(msg.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60}, Txt: []string{"wulf-callback"}})
		return
	case dns.TypeAAAA:
		return
	case dns.TypeANY:
		msg.Answer = append(msg.Answer,
			&dns.NS{Hdr: dns.RR_Header{Name: s.dnsZone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: s.soaNS},
			&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: s.dnsA},
		)
		return
	}

	msg.Ns = append(msg.Ns, s.soaRecord())
}

func (s *server) soaRecord() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: s.dnsZone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 60},
		Ns:      s.soaNS,
		Mbox:    ensureFQDN("hostmaster." + s.cfg.CallbackDomain),
		Serial:  uint32(time.Now().UTC().Unix()),
		Refresh: 300,
		Retry:   60,
		Expire:  86400,
		Minttl:  60,
	}
}

func (s *sink) Write(ctx context.Context, event eventEnvelope) error {
	line, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	file, err := s.fileFor(event.Type)
	if err == nil {
		_, err = file.Write(line)
	}
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("append jsonl: %w", err)
	}

	if err := s.uploader.Upload(ctx, event); err != nil {
		return fmt.Errorf("upload r2: %w", err)
	}
	return nil
}

func (s *sink) fileFor(eventType string) (*os.File, error) {
	if file, ok := s.files[eventType]; ok {
		return file, nil
	}
	path := filepath.Join(s.logDir, eventType+".jsonl")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	s.files[eventType] = file
	return file, nil
}

func (noopUploader) Upload(context.Context, eventEnvelope) error { return nil }

func (u *r2Uploader) Upload(ctx context.Context, event eventEnvelope) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	key := fmt.Sprintf("events/%s/%s/%s.json",
		time.Now().UTC().Format("2006/01/02"),
		event.Type,
		event.ID,
	)
	_, err = u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/json"),
	})
	return err
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func headerMap(h http.Header) map[string][]string {
	out := make(map[string][]string, len(h))
	for k, v := range h {
		copied := append([]string(nil), v...)
		out[strings.ToLower(k)] = copied
	}
	return out
}

func schemeOf(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return strings.ToLower(proto)
	}
	return "http"
}

func ensureFQDN(s string) string {
	if strings.HasSuffix(s, ".") {
		return s
	}
	return s + "."
}

func newID() string {
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UTC().UnixNano())
	}
	return strings.TrimRight(strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])), "=")
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		log.Fatalf("missing required env %s", key)
	}
	return v
}

func envOr(key, fallback string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	return v
}

func durationOr(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		log.Fatalf("invalid duration %s: %v", key, err)
	}
	return d
}

func int64Or(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	var out int64
	if _, err := fmt.Sscan(v, &out); err != nil {
		log.Fatalf("invalid int %s: %v", key, err)
	}
	return out
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, io.EOF) {
		return "EOF"
	}
	return err.Error()
}
