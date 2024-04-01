package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/go-ntlmssp"
)

type DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

func WrapDialContext(dialContext DialContext, isNtlm bool, proxyAddress, proxyUsername, proxyPassword, proxyDomain string) DialContext {
	if isNtlm {
		return wrapNTLM(dialContext, proxyAddress, proxyUsername, proxyPassword, proxyDomain)
	}
	return wrapBasic(dialContext, proxyAddress, proxyUsername, proxyPassword, proxyDomain)
}

func wrapBasic(dialContext DialContext, proxyAddress, proxyUsername, proxyPassword, proxyDomain string) DialContext {
	URL, err := url.Parse(proxyAddress)
	if err != nil {
		log.Fatalln(err)
	}
	proxyAddress = URL.Host
	auth := base64.StdEncoding.EncodeToString([]byte(proxyUsername + ":" + proxyPassword))
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, network, proxyAddress)
		for err != nil {
			conn, err = dialContext(ctx, network, proxyAddress)
			log.Println("dial to proxy address:", proxyAddress, " failed")
		}
		header := make(http.Header)
		header.Set("Proxy-Authorization", "Basic "+auth)
		header.Set("Proxy-Connection", "Keep-Alive")
		connect := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: header,
		}
		log.Println("writting request CONNECT to proxy")
		if err := connect.Write(conn); err != nil {
			log.Printf("Could not write authorization to proxy: %s\n\r", err)
			return conn, err
		}
		log.Println("reading request CONNECT from proxy")
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, connect)
		if err != nil {
			log.Printf("Could not read response from proxy: %s\n\r", err)
			return conn, err
		}
		if resp.StatusCode != http.StatusOK {
			log.Println("error with status code: ", resp.StatusCode)
			return conn, errors.New(http.StatusText(resp.StatusCode))
		}
		return conn, nil
	}
}

func wrapNTLM(dialContext DialContext, proxyAddress, proxyUsername, proxyPassword, proxyDomain string) DialContext {
	URL, err := url.Parse(proxyAddress)
	if err != nil {
		log.Fatalln(err)
	}
	proxyAddress = URL.Host
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialContext(ctx, network, proxyAddress)
		for err != nil {
			conn, err = dialContext(ctx, network, proxyAddress)
			log.Printf("ntlm> Could not call dial context with proxy: %s\n\r", err)
		}
		// NTLM Step 1: Send Negotiate Message
		negotiateMessage, err := ntlmssp.NewNegotiateMessage(proxyDomain, "")
		if err != nil {
			log.Printf("ntlm> Could not negotiate domain '%s': %s\n\r", proxyDomain, err)
			return conn, err
		}
		log.Printf("ntlm> NTLM negotiate message: '%s'\n\r", base64.StdEncoding.EncodeToString(negotiateMessage))
		header := make(http.Header)
		header.Set("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(negotiateMessage)))
		header.Set("Proxy-Connection", "Keep-Alive")
		connect := &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: header,
		}
		if err := connect.Write(conn); err != nil {
			log.Printf("ntlm> Could not write negotiate message to proxy: %s\n\r", err)
			return conn, err
		}
		log.Printf("ntlm> Successfully sent negotiate message to proxy\n\r")
		// N\TLM Step 2: Receive Challenge Message
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, connect)
		if err != nil {
			log.Printf("ntlm> Could not read response from proxy: %s\n\r", err)
			return conn, err
		}
		_, err = io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("ntlm> Could not read response body from proxy: %s\n\r", err)
			return conn, err
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusForbidden {
			return dialContext(ctx, network, addr)
		}
		if resp.StatusCode != http.StatusProxyAuthRequired {
			log.Printf("ntlm> Expected %d as return status, got: %d\n\r", http.StatusProxyAuthRequired, resp.StatusCode)
			return conn, errors.New(http.StatusText(resp.StatusCode))
		}

		challenge := strings.Split(resp.Header.Get("Proxy-Authenticate"), " ")
		if len(challenge) < 2 {
			log.Printf("ntlm> The proxy did not return an NTLM challenge, got: '%s'", resp.Header.Get("Proxy-Authenticate"))
			return conn, errors.New("no NTLM challenge received")
		}
		log.Printf("ntlm> NTLM challenge: '%s'\n\r", challenge[1])
		challengeMessage, err := base64.StdEncoding.DecodeString(challenge[1])
		if err != nil {
			log.Printf("ntlm> Could not base64 decode the NTLM challenge: %s\n\r", err)
			return conn, err
		}
		// NTLM Step 3: Send Authorization Message
		log.Printf("ntlm> Processing NTLM challenge with username '%s' and password with length %d\n\r", proxyUsername, len(proxyPassword))
		authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, proxyUsername, proxyPassword, proxyDomain != "")
		if err != nil {
			log.Printf("ntlm> Could not process the NTLM challenge: %s\n\r", err)
			return conn, err
		}
		log.Printf("ntlm> NTLM authorization: '%s'\n\r", base64.StdEncoding.EncodeToString(authenticateMessage))
		header.Set("Proxy-Authorization", fmt.Sprintf("NTLM %s", base64.StdEncoding.EncodeToString(authenticateMessage)))
		connect = &http.Request{
			Method: "CONNECT",
			URL:    &url.URL{Opaque: addr},
			Host:   addr,
			Header: header,
		}
		if err := connect.Write(conn); err != nil {
			log.Printf("ntlm> Could not write authorization to proxy: %s\n\r", err)
			return conn, err
		}
		resp, err = http.ReadResponse(br, connect)
		if err != nil {
			log.Printf("ntlm> Could not read response from proxy: %s\n\r", err)
			return conn, err
		}
		if resp.StatusCode != http.StatusOK {
			log.Printf("ntlm> Expected %d as return status, got: %d\n\r", http.StatusOK, resp.StatusCode)
			return conn, errors.New(http.StatusText(resp.StatusCode))
		}
		// Succussfully authorized with NTLM
		log.Printf("ntlm> Successfully injected NTLM to connection\n\r")
		return conn, nil
	}
}
