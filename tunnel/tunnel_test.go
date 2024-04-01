package tunnel

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

func TestCryptDecrypt(t *testing.T) {
	message := "Hello World!! I'm testing an encrypter and decrypter function!! the ways is encrypting this message and comparing with the decrypted message!! let's test the funcs now!!"
	key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	buffer, err := encrypt([]byte(message), key)
	if err != nil {
		t.FailNow()
	}
	buffer, err = decrypt(buffer, key)
	if err != nil {
		t.FailNow()
	}
	if message != string(buffer) {
		t.FailNow()
	}
}

func TestHash(t *testing.T) {
	message := "Hello World!! I'm testing an encrypter and decrypter function!! the ways is encrypting this message and comparing with the decrypted message!! let's test the funcs now!!"
	hash := GetHashSHA256([]byte(message))
	if len(hash) != 32 {
		t.FailNow()
	}
}

func TestCheckHash(t *testing.T) {
	message := "Hello World!! I'm testing an encrypter and decrypter function!! the ways is encrypting this message and comparing with the decrypted message!! let's test the funcs now!!"
	hash := GetHashSHA256([]byte(message))
	if !CheckHashSHA256([]byte(message), hash) {
		t.FailNow()
	}
}

func TestHashUnHashBuffer(t *testing.T) {
	message := "Hello World!! I'm testing an encrypter and decrypter function!! the ways is encrypting this message and comparing with the decrypted message!! let's test the funcs now!!"
	buffer := hashBuffer([]byte(message))
	buffer, err := unhashBuffer(buffer)
	if err != nil {
		t.FailNow()
	}
	if message != string(buffer) {
		t.FailNow()
	}
}

func TestTunnelDialErr(t *testing.T) {
	DebugTest = true
	key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	ws := make(chan int)
	//Run server
	go func() {
		ls, err := net.Listen("tcp", "127.0.0.1:8080")
		for err != nil {
			ls, err = net.Listen("tcp", "127.0.0.1:8080")
		}
		ws <- 0
		conn, err := ls.Accept()
		for err != nil {
			conn, err = ls.Accept()
		}
		tunnel := NewTunnel(conn, key)
		go tunnel.RunServer()
		<-ws
		tunnel.Stop()
	}()
	<-ws
	log.Println("starting the tunnel client")
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	for err != nil {
		conn, err = net.Dial("tcp", "127.0.0.1:8080")
	}
	tunnel := NewTunnel(conn, key)
	go tunnel.RunClient()
	client := http.Client{
		Transport: &http.Transport{
			Dial:                  tunnel.Dial,
			IdleConnTimeout:       time.Second * 30,
			TLSHandshakeTimeout:   time.Second * 30,
			ResponseHeaderTimeout: time.Second * 30,
			ExpectContinueTimeout: time.Second * 30,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunnel.Dial(network, addr)
			},
		},
	}
	time.Sleep(time.Second * 2)
	log.Println("sending http request throught tunnel")
	_, err = client.Get("http://unknown-domain-domain-unknown.unknown.com")
	if err == nil {
		log.Println(err)
		t.Fail()
	}
	tunnel.Stop()
	ws <- 0
}

func TestTunnelClientConnCloseErr(t *testing.T) {
	DebugTest = true
	key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	ws := make(chan int)
	//Run server
	go func() {
		ls, err := net.Listen("tcp", "127.0.0.1:8080")
		for err != nil {
			ls, err = net.Listen("tcp", "127.0.0.1:8080")
		}
		ws <- 0
		conn, err := ls.Accept()
		for err != nil {
			conn, err = ls.Accept()
		}
		tunnel := NewTunnel(conn, key)
		go tunnel.RunServer()
		<-ws
		tunnel.Stop()
	}()
	<-ws
	log.Println("starting the tunnel client")
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	for err != nil {
		conn, err = net.Dial("tcp", "127.0.0.1:8080")
	}
	tunnel := NewTunnel(conn, key)
	go tunnel.RunClient()
	client := http.Client{
		Transport: &http.Transport{
			Dial:                  tunnel.Dial,
			IdleConnTimeout:       time.Second * 30,
			TLSHandshakeTimeout:   time.Second * 30,
			ResponseHeaderTimeout: time.Second * 30,
			ExpectContinueTimeout: time.Second * 30,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunnel.Dial(network, addr)
			},
		},
	}
	time.Sleep(time.Second * 2)
	log.Println("sending http request throught tunnel")
	go func() {
		time.Sleep(time.Second)
		conn.Close()
	}()
	time.Sleep(time.Second)
	_, err = client.Get("http://www.google.com")
	if err == nil {
		log.Println(err)
		t.Fail()
	}
	tunnel.Stop()
	ws <- 0
}

func TestTunnelConcurrency(t *testing.T) {
	DebugTest = true
	key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	ws := make(chan int)
	//Run server
	go func() {
		ls, err := net.Listen("tcp", "127.0.0.1:8080")
		for err != nil {
			ls, err = net.Listen("tcp", "127.0.0.1:8080")
		}
		ws <- 0
		conn, err := ls.Accept()
		for err != nil {
			conn, err = ls.Accept()
		}
		tunnel := NewTunnel(conn, key)
		go tunnel.RunServer()
		<-ws
		tunnel.Stop()
	}()
	<-ws
	log.Println("starting the tunnel client")
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	for err != nil {
		conn, err = net.Dial("tcp", "127.0.0.1:8080")
	}
	tunnel := NewTunnel(conn, key)
	go tunnel.RunClient()
	wg := sync.WaitGroup{}
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := http.Client{
				Transport: &http.Transport{
					Dial:                  tunnel.Dial,
					IdleConnTimeout:       time.Second * 30,
					TLSHandshakeTimeout:   time.Second * 30,
					ResponseHeaderTimeout: time.Second * 30,
					ExpectContinueTimeout: time.Second * 30,
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						return tunnel.Dial(network, addr)
					},
				},
			}
			time.Sleep(time.Second * 2)
			log.Println("sending http request throught tunnel")
			resp, err := client.Get("http://www.google.com")
			if err != nil {
				log.Println(err)
				t.Fail()
			}
			defer resp.Body.Close()
			data, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fail()
			}
			fmt.Println(string(data))
		}()
	}
	wg.Wait()
	tunnel.Stop()
	ws <- 0
}

func TestClient(t *testing.T) {
	keyd, err := os.ReadFile("./server/key.txt")
	// key, err := NewAESKey()
	if err != nil {
		t.FailNow()
	}
	key := AESKey(keyd)
	log.Println("starting the tunnel client")
	conn, err := net.Dial("tcp", "127.0.0.1:8080")
	for err != nil {
		conn, err = net.Dial("tcp", "127.0.0.1:8080")
	}
	tunnel := NewTunnel(conn, key)
	go tunnel.RunClient()
	client := http.Client{
		Transport: &http.Transport{
			Dial:                  tunnel.Dial,
			IdleConnTimeout:       time.Second * 30,
			TLSHandshakeTimeout:   time.Second * 30,
			ResponseHeaderTimeout: time.Second * 30,
			ExpectContinueTimeout: time.Second * 30,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tunnel.Dial(network, addr)
			},
		},
	}
	time.Sleep(time.Second * 2)
	log.Println("sending http request throught tunnel")
	resp, err := client.Get("http://www.google.com")
	if err != nil {
		log.Println(err)
		t.FailNow()
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.FailNow()
	}
	fmt.Println(string(data))
	tunnel.Stop()
}
