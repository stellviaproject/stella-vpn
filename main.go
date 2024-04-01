package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"

	"github.com/elazarl/goproxy"
	"github.com/stellviaproject/stella-vpn/transport"
	"github.com/stellviaproject/stella-vpn/tunnel"
	"golang.org/x/net/idna"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Key      string `json:"key"`
}

var db map[string]*User
var rw sync.RWMutex

var buffer = &bytes.Buffer{}

func main() {
	log.SetOutput(io.MultiWriter(buffer, os.Stdout))
	mode := flag.String("mode", "server", "the application starts in this mode")
	user := flag.String("auth", "auth.json", "a json file containning all users")
	enableTls := flag.Bool("tls", false, "use tls for handling connections")
	cfgFile := flag.String("cfg", "./config.json", "the configuration file of vpn client")
	flag.Parse()
	switch *mode {
	case "server":
		PORT := os.Getenv("PORT")
		port, err := strconv.Atoi(PORT)
		if err != nil {
			port = 8080
		}
		var tlsConfig tls.Config
		if *enableTls {
			CERT := os.Getenv("CERT")
			if _, err := os.Stat(CERT); err != nil {
				log.Printf("error loading file %s: %v\n", CERT, err)
				CERT = "./cert.pem"
			}
			KEY := os.Getenv("KEY")
			if _, err := os.Stat(KEY); err != nil {
				log.Printf("error loading file %s: %v\n", KEY, err)
				KEY = "./key.pem"
			}
			cert, err := os.ReadFile(CERT)
			if err != nil {
				log.Fatalln(err)
			}
			key, err := os.ReadFile(KEY)
			if err != nil {
				log.Fatalln(err)
			}
			tlsCert, err := tls.X509KeyPair(cert, key)
			if err != nil {
				log.Fatalln(err)
			}
			tlsConfig = tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			}
		}
		//load users
		db = map[string]*User{}
		if data, err := os.ReadFile(*user); err != nil {
			log.Println(err)
			db["admin"] = &User{
				Username: "admin",
				Password: "admin",
			}
		} else if err := json.Unmarshal(data, &db); err != nil {
			log.Println(err)
			db["admin"] = &User{
				Username: "admin",
				Password: "admin",
			}
		}
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Println(err)
		}
		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT)
		shouldClose := false
		log.Printf("server listen to: 0.0.0.0:%v\n", port)
		for !shouldClose {
			select {
			case <-sigs:
				shouldClose = true
				continue
			default:
			}
			conn, err := listener.Accept()
			log.Printf("server accept connection to: %v\n", conn.RemoteAddr())
			if err != nil {
				log.Println(err)
			} else if *enableTls {
				log.Printf("using tls with connection to: %v\n", conn.RemoteAddr())
				go handleConnTLS(conn, tlsConfig.Clone())
			} else {
				go handleConn(conn)
			}
		}
	case "client":
		if *cfgFile == "" {
			log.Fatalln("the path of configuration file could not be empty")
			return
		}
		if _, err := os.Stat(*cfgFile); err != nil && os.IsNotExist(err) {
			cfg := &TunnelConfig{
				AppURL:   "-",
				Port:     8080,
				Username: "-",
				Password: "-",
				OTP:      "",
				Proxy: ProxyConfig{
					URL:      "http://0.0.0.0:0",
					Username: "-",
					Password: "-",
					Domain:   "-",
					Ntlm:     false,
				},
			}
			if err := cfg.SaveConfig(*cfgFile); err != nil {
				log.Fatalln(err)
			}
			log.Println("the configuration file has been created")
			return
		}
		cfg := TunnelConfig{}
		if err := (&cfg).LoadConfig(*cfgFile); err != nil {
			log.Fatalln(err)
		}
		max := cfg.MaxRetry
		if max < 0 {
			max = math.MaxInt
		}
		for i := 0; i < max; i++ {
			Connect(cfg)
		}
	}
}

func handleConnTLS(conn net.Conn, tlsConfig *tls.Config) {
	log.Printf("create the tls server connection to: %v\n", conn.RemoteAddr())
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("tls hanshake failed to %v with error: %v\n", conn.RemoteAddr(), err)
		return
	}
	log.Printf("tls handshake succes with connection to %v\n", conn.RemoteAddr())
	handleConn(conn)
}

func WriteJSON(status int, conn net.Conn, v any) {
	log.Printf("writing json to client with addr: %v\n", conn.RemoteAddr())
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("failed to marshall for client %v with error %v\n", conn.RemoteAddr(), err)
		conn.Close()
		return
	}
	res := &http.Response{
		StatusCode: status,
		Close:      false,
		Body:       io.NopCloser(bytes.NewReader(data)),
	}
	if err := res.Write(conn); err != nil {
		log.Printf("failed to send response to client %v with error %v\n", conn.RemoteAddr(), err)
		conn.Close()
		log.Println(err)
	}
}

func handleConn(conn net.Conn) {
	log.Printf("running handler on connection: %v\n", conn.RemoteAddr())
	defer conn.Close()
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Println(err)
		return
	}
	switch req.Method {
	case "GET":
		if req.URL.Path == "/log" {
			html := `<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Logs</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f0f0f0;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #fff;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .log-content {
            white-space: pre-wrap; /* Mantiene los saltos de línea y espacios */
            font-size: 14px;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Logs</h1>
        <div class="log-content">
` + strings.ReplaceAll(string(buffer.Bytes()), "\n", "<br/>") + `
        </div>
    </div>
</body>
</html>`
			res := &http.Response{
				StatusCode: http.StatusOK,
				Header:     req.Header,
				Request:    req,
				Close:      true,
				Body:       io.NopCloser(bytes.NewReader([]byte(html))),
			}
			if err := res.Write(conn); err != nil {
				log.Println(err)
			}
		}
	case "POST":
		if req.URL.Path == TunnelPath {
			log.Printf("client loggin from addr %v\n", conn.RemoteAddr())
			data, err := io.ReadAll(req.Body)
			if err != nil {
				log.Println(err)
				return
			}
			user := &User{}
			if err := json.Unmarshal(data, &user); err != nil {
				log.Printf("unmarshal json with user failed from %v with error %v\n", conn.RemoteAddr(), err)
				return
			}
			rw.RLock()
			dbUser := db[user.Username]
			rw.RUnlock()
			if user != nil && dbUser.Password == user.Password {
				log.Printf("creating aeskey for connection %v\n", conn.RemoteAddr())
				key, err := tunnel.NewAESKey()
				if err != nil {
					log.Println(err)
					return
				}
				log.Printf("sending key to %v\n", conn.RemoteAddr())
				data, err := json.Marshal(&User{
					Key: key.ToString(),
				})
				if err != nil {
					log.Println(err)
					return
				}
				buffer := &bytes.Buffer{}
				err = binary.Write(buffer, binary.LittleEndian, int32(len(data)))
				if err != nil {
					log.Println(err)
					return
				}
				err = binary.Write(buffer, binary.LittleEndian, data)
				if err != nil {
					log.Println(err)
					return
				}
				_, err = conn.Write(buffer.Bytes())
				if err != nil {
					log.Println(err)
					return
				}
				log.Printf("creating tunnel for connection %v\n", conn.RemoteAddr())
				tn := tunnel.NewTunnel(conn, key)
				go func() {
					time.Sleep(time.Second)
					log.Printf("sending connect to %v\n", conn.RemoteAddr())
					tn.DoConnectRes()
				}()
				log.Printf("running tunnel for connection %v\n", conn.RemoteAddr())
				tn.RunServer()
			} else {
				log.Printf("loggin failed from %v with error %v\n", conn.RemoteAddr(), err)
				return
			}
		}
	}
}

func Connect(cfg TunnelConfig) {
	InitURL(cfg)
	retry, max := 0, cfg.MaxRetry
	if max < 0 {
		max = math.MaxInt
	}
	log.Println("init tunnel")
	conn, key, err := InitTunnel(cfg)
	for err != nil && retry < max {
		conn, key, err = InitTunnel(cfg)
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
			log.Printf("proxy listen to 0.0.0.0:%d\n", port)
			log.Println(http.ListenAndServe(fmt.Sprintf(":%d", port), proxy))
		}()
	}
	tn.RunClient()
}

func InitURL(cfg TunnelConfig) {
	var err error
	AppURL, err = url.Parse(cfg.AppURL)
	if err != nil {
		log.Fatalln(err)
	}
}

func InitTunnel(cfg TunnelConfig) (net.Conn, tunnel.AESKey, error) {
	URL, err := url.Parse(AppURL.String() + TunnelPath)
	if err != nil {
		log.Fatalln(err)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("create GET HTTP request to %s%s\n", AppURL.String(), TunnelPath)
	req, err := http.NewRequest("POST", URL.String(), bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	req.URL = URL
	log.Printf("getting connection\n")
	conn, err := GetConn(req, GetTransport(cfg.Proxy))
	if err != nil {
		return nil, nil, err
	}
	log.Printf("reading login response\n")
	length := int32(0)
	err = binary.Read(conn, binary.LittleEndian, &length)
	if err != nil {
		return nil, nil, err
	}
	data = make([]byte, length)
	_, err = conn.Read(data)
	if err != nil {
		return nil, nil, err
	}
	user := &User{}
	log.Printf("decoding user for getting the key\n")
	if err := json.Unmarshal(data, user); err != nil {
		return nil, nil, err
	}
	log.Printf("decoding the key\n")
	key, err := tunnel.KeyFromStr(user.Key)
	if err != nil {
		return nil, nil, err
	}
	return conn, key, nil
}

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

const TunnelPath = "/api/login"

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
