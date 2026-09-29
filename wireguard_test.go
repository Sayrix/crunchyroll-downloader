package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// TestWireGuardLoopback proves that an HTTP request crosses a real WireGuard
// handshake and the private TCP/IP stack without an OS tunnel or public server.
func TestWireGuardLoopback(t *testing.T) {
	curve := ecdh.X25519()
	serverKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverIP := netip.MustParseAddr("10.42.0.1")
	serverTun, serverNet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	server := device.NewDevice(serverTun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "test WireGuard: "))
	defer server.Close()
	serverConfig := fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.42.0.2/32\n",
		hex.EncodeToString(serverKey.Bytes()), hex.EncodeToString(clientKey.PublicKey().Bytes()))
	if err := server.IpcSet(serverConfig); err != nil {
		t.Fatal(err)
	}
	if err := server.Up(); err != nil {
		t.Fatal(err)
	}
	status, err := server.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	var listenPort int
	for _, line := range strings.Split(status, "\n") {
		if value, ok := strings.CutPrefix(line, "listen_port="); ok {
			listenPort, err = strconv.Atoi(value)
			if err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if listenPort == 0 {
		t.Fatal("WireGuard server did not open a UDP port")
	}

	listener, err := serverNet.ListenTCP(&net.TCPAddr{IP: net.ParseIP("10.42.0.1"), Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "through WireGuard")
	})}
	defer httpServer.Close()
	go httpServer.Serve(listener)
	dnsListener, err := serverNet.ListenUDP(&net.UDPAddr{IP: net.ParseIP("10.42.0.1"), Port: 53})
	if err != nil {
		t.Fatal(err)
	}
	defer dnsListener.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, address, err := dnsListener.ReadFrom(buf)
			if err != nil {
				return
			}
			var parser dnsmessage.Parser
			header, err := parser.Start(buf[:n])
			if err != nil {
				continue
			}
			question, err := parser.Question()
			if err != nil || question.Type != dnsmessage.TypeA {
				continue
			}
			builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true})
			if builder.StartQuestions() != nil || builder.Question(question) != nil || builder.StartAnswers() != nil {
				continue
			}
			if builder.AResource(dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60}, dnsmessage.AResource{A: [4]byte{10, 42, 0, 1}}) != nil {
				continue
			}
			response, err := builder.Finish()
			if err == nil {
				_, _ = dnsListener.WriteTo(response, address)
			}
		}
	}()

	config := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.42.0.2/32\nDNS = 10.42.0.1\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 127.0.0.1:%d\n",
		base64.StdEncoding.EncodeToString(clientKey.Bytes()), base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), listenPort)
	path := filepath.Join(t.TempDir(), "tunnel.conf")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	client, cleanup, err := startWireGuardHTTP(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	client.Timeout = 5 * time.Second
	previousClient := requestClient
	requestClient = client
	defer func() { requestClient = previousClient }()
	body, err := downloadPart("http://vpn-only.test:8080/")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "through WireGuard" {
		t.Fatalf("response body = %q, want a response from the tunneled server", body)
	}
}
