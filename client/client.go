package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"time"
	"unicode"

	"github.com/elazarl/goproxy"
	"github.com/stellviaproject/stella-vpn/dto"
	"github.com/stellviaproject/stella-vpn/transport"
	"github.com/stellviaproject/stella-vpn/tunnel"
	"golang.org/x/net/idna"
)

type ProxyConfig struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Domain   string `json:"domain"`
	Ntlm     bool   `json:"ntlm"`
}

type TunnelConfig struct {
	AppURL   string      `json:"url"`
	Port     int         `json:"port"`
	Username string      `json:"username"`
	Password string      `json:"password"`
	OTP      string      `json:"otp"`
	Proxy    ProxyConfig `json:"proxy"`
	MaxRetry int         `json:"max-retry"`
}

func (config *TunnelConfig) LoadConfig(fileName string) error {
	data, err := os.ReadFile(fileName)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, config); err != nil {
		return err
	}
	return nil
}

func (config *TunnelConfig) SaveConfig(fileName string) error {
	data, err := json.MarshalIndent(config, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(fileName, data, os.ModePerm|os.ModeDevice)
}

var (
	tn             *tunnel.Tunnel
	isProxyRunning bool //?
	AppURL         *url.URL
)

func Connect(cfg TunnelConfig) error {
	InitURL(cfg)
	key, cookies, err := Login(cfg)
	retry, max := 0, cfg.MaxRetry
	if max < 0 {
		max = math.MaxInt
	}
	for err != nil && retry < max {
		key, cookies, err = Login(cfg)
		if err != nil {
			log.Println(err)
		}
		retry++
	}
	if err != nil {
		log.Fatalf("client can't login: %v\n", err)
	}
	log.Println("loggin with key: ", key)
	conn, err := InitTunnel(cfg.Proxy, cookies)
	for err != nil && retry < max {
		conn, err = InitTunnel(cfg.Proxy, cookies)
		if err != nil {
			log.Println(err)
		}
		retry++
	}
	if err != nil {
		log.Fatalln("client can't start the tunnel")
	}
	defer conn.Close()
	RunTunnel(cfg.Port, conn, key)
	return nil
}

func InitURL(cfg TunnelConfig) {
	var err error
	AppURL, err = url.Parse(cfg.AppURL)
	if err != nil {
		log.Fatalln(err)
	}
}

func GetTransport(cfg ProxyConfig) *http.Transport {
	dialer := net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: time.Duration(math.MaxInt64),
	}
	var Tr *http.Transport
	if cfg.URL != "" {
		Tr = &http.Transport{
			Dial: dialer.Dial,
			DialContext: transport.WrapDialContext(
				dialer.DialContext,
				cfg.Ntlm,
				cfg.URL,
				cfg.Username,
				cfg.Password,
				cfg.Domain,
			),
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   30 * time.Second,
			IdleConnTimeout:       time.Duration(math.MaxInt64),
			ResponseHeaderTimeout: 30 * time.Second,
		}
	} else {
		Tr = &http.Transport{
			Dial:                  dialer.Dial,
			DialContext:           dialer.DialContext,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			TLSHandshakeTimeout:   30 * time.Second,
			IdleConnTimeout:       time.Duration(math.MaxInt64),
			ResponseHeaderTimeout: 30 * time.Second,
		}
	}
	return Tr
}

func NewClient(cfg ProxyConfig) *http.Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalln(err)
	}
	return &http.Client{
		Jar:       jar,
		Transport: GetTransport(cfg),
		Timeout:   30 * time.Second,
	}
}

func Login(cfg TunnelConfig) (key tunnel.AESKey, cookies []*http.Cookie, err error) {
	client := NewClient(cfg.Proxy)
	client.Timeout = time.Hour
	form := &dto.LoginForm{
		Username: cfg.Username,
		Password: cfg.Password,
		OTP:      cfg.OTP,
	}
	formData, err := json.Marshal(form)
	if err != nil {
		return nil, nil, err
	}
	log.Printf("logging to %s/login\n", AppURL.String())
	res, err := client.Post(AppURL.String()+"/login", "application/json", bytes.NewBuffer(formData))
	if err != nil {
		return nil, nil, err
	}
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	//check-up response
	lg := &dto.LoginResponse{}
	if err = json.Unmarshal(body, lg); err != nil {
		return nil, nil, err
	}
	if lg.Err != "" {
		return nil, nil, errors.New(lg.Err)
	}
	log.Println("logging successfully")
	key, err = tunnel.KeyFromStr(lg.Key)
	if err != nil {
		return
	}
	return key, res.Cookies(), nil
}

func InitTunnel(cfg ProxyConfig, cookies []*http.Cookie) (net.Conn, error) {
	// Tr := GetTransport(cfg)
	// //run vpn connection on server side
	// log.Printf("dial for getting tunnel connection to %s\n", AppURL.Host)
	// var port string
	// if AppURL.Scheme == "https" {
	// 	port = ":443"
	// } else {
	// 	port = ":80"
	// }
	// conn, err := Tr.DialContext(context.Background(), "tcp", AppURL.Host+port)
	// if err != nil {
	// 	return nil, err
	// }
	URL, err := url.Parse(AppURL.String() + "/api/vpn/run")
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("create GET HTTP request to %s/api/vpn/run\n", AppURL.Host)
	req, err := http.NewRequest("GET", URL.String(), nil)
	if err != nil {
		return nil, err
	}
	req.URL = URL
	log.Println("set cookies to request for using logging session")
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	return GetConn(req, GetTransport(cfg))
	// if AppURL.Scheme == "https" {
	// 	log.Println("use tls for this connection")
	// 	tlsConfig := &tls.Config{
	// 		InsecureSkipVerify: true,
	// 	}
	// 	log.Println("doing tls handshake...")
	// 	tlsConn := tls.Client(conn, tlsConfig)
	// 	err := tlsConn.Handshake()
	// 	if err != nil {
	// 		log.Println("tls handshake failed")
	// 		return nil, err
	// 	}
	// 	conn = tlsConn
	// }
	// log.Println("writting HTTP request")
	// if err := req.Write(conn); err != nil {
	// 	return nil, err
	// }
	// if tcpConn, ok := conn.(*net.TCPConn); ok {
	// 	log.Println("set keep alive to connection")
	// 	tcpConn.SetKeepAlive(true)
	// 	tcpConn.SetKeepAlivePeriod(time.Hour * 24)
	// }
	// log.Println("GET request successfully")
	// return conn, nil
}

func RunTunnel(port int, conn net.Conn, key tunnel.AESKey) {
	log.Println("running tunnel...")
	//run vpn connection on client side
	tn = tunnel.NewTunnel(conn, key)
	if !isProxyRunning {
		isProxyRunning = true
		go func() {
			proxy := goproxy.NewProxyHttpServer()
			proxy.Verbose = true
			proxy.Tr = &http.Transport{
				Dial: tn.Dial,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return tn.Dial(network, addr)
				},
			}
			log.Println(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
		}()
	}
	tn.RunClient()
}

func GetConn(req *http.Request, Tr *http.Transport) (net.Conn, error) {
	ctx := req.Context()
	if req.URL == nil {
		return nil, errors.New("nil URL in HTTP Request")
	}
	addr := canonicalAddr(req.URL)
	conn, err := Tr.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if req.URL.Scheme == "https" {
		var firstTLSHost string
		if firstTLSHost, _, err = net.SplitHostPort(addr); err != nil {
			return nil, err
		}
		conn, err = addTLS(conn, ctx, req, firstTLSHost, Tr.TLSClientConfig, Tr)
		if err != nil {
			return nil, err
		}
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	return conn, nil
}

func hasToken(v, token string) bool {
	if len(token) > len(v) || token == "" {
		return false
	}
	if v == token {
		return true
	}
	for sp := 0; sp <= len(v)-len(token); sp++ {
		// Check that first character is good.
		// The token is ASCII, so checking only a single byte
		// is sufficient. We skip this potential starting
		// position if both the first byte and its potential
		// ASCII uppercase equivalent (b|0x20) don't match.
		// False positives ('^' => '~') are caught by EqualFold.
		if b := v[sp]; b != token[0] && b|0x20 != token[0] {
			continue
		}
		// Check that start pos is on a valid token boundary.
		if sp > 0 && !isTokenBoundary(v[sp-1]) {
			continue
		}
		// Check that end pos is on a valid token boundary.
		if endPos := sp + len(token); endPos != len(v) && !isTokenBoundary(v[endPos]) {
			continue
		}
		if EqualFold(v[sp:sp+len(token)], token) {
			return true
		}
	}
	return false
}

// lower returns the ASCII lowercase version of b.
func lower(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// EqualFold is strings.EqualFold, ASCII only. It reports whether s and t
// are equal, ASCII-case-insensitively.
func EqualFold(s, t string) bool {
	if len(s) != len(t) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if lower(s[i]) != lower(t[i]) {
			return false
		}
	}
	return true
}

func isTokenBoundary(b byte) bool {
	return b == ' ' || b == ',' || b == '\t'
}

type tlsHandshakeTimeoutError struct{}

func (tlsHandshakeTimeoutError) Timeout() bool   { return true }
func (tlsHandshakeTimeoutError) Temporary() bool { return true }
func (tlsHandshakeTimeoutError) Error() string   { return "net/http: TLS handshake timeout" }

func addTLS(conn net.Conn, ctx context.Context, r *http.Request, name string, cfg *tls.Config, tr *http.Transport) (net.Conn, error) {
	cfg = cfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = name
	}
	if requiresHTTP1(r) {
		cfg.NextProtos = nil
	}
	tlsConn := tls.Client(conn, cfg)
	errc := make(chan error, 2)
	var timer *time.Timer
	if d := tr.TLSHandshakeTimeout; d != 0 {
		timer = time.AfterFunc(d, func() {
			errc <- tlsHandshakeTimeoutError{}
		})
	}
	go func() {
		err := tlsConn.HandshakeContext(ctx)
		if timer != nil {
			timer.Stop()
		}
		errc <- err
	}()
	if err := <-errc; err != nil {
		conn.Close()
		return nil, err
	}
	return tlsConn, nil
}

var portMap = map[string]string{
	"http":   "80",
	"https":  "443",
	"socks5": "1080",
}

func Is(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func idnaASCII(v string) (string, error) {
	if Is(v) {
		return v, nil
	}
	return idna.Lookup.ToASCII(v)
}

func idnaASCIIFromURL(url *url.URL) string {
	addr := url.Hostname()
	if v, err := idnaASCII(addr); err == nil {
		addr = v
	}
	return addr
}

func canonicalAddr(url *url.URL) string {
	port := url.Port()
	if port == "" {
		port = portMap[url.Scheme]
	}
	return net.JoinHostPort(idnaASCIIFromURL(url), port)
}

func requiresHTTP1(r *http.Request) bool {
	return hasToken(r.Header.Get("Connection"), "upgrade") &&
		EqualFold(r.Header.Get("Upgrade"), "websocket")
}
