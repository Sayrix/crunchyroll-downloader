package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// startWireGuardHTTP creates a private network stack for this process. The
// WireGuard UDP socket uses the host's current route (including an existing
// VPN), while HTTP connections and DNS use the WireGuard peer. No OS interface,
// route, or service is installed.
func startWireGuardHTTP(path string) (*http.Client, func(), error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("reading WireGuard config: %w", err)
	}
	cfg, err := parseWireGuardConfig(data)
	if err != nil {
		return nil, nil, err
	}
	tun, network, err := netstack.CreateNetTUN(cfg.addresses, cfg.dns, cfg.mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("creating WireGuard network stack: %w", err)
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "WireGuard: "))
	if err := dev.IpcSet(cfg.ipcConfig()); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("configuring WireGuard peer: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("starting WireGuard peer: %w", err)
	}

	// The transport has no proxy or fallback dialer: a failed tunnel fails the
	// download instead of silently sending Crunchyroll traffic through the host.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, networkType, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return network.DialContext(ctx, networkType, address)
	}
	transport.ForceAttemptHTTP2 = true
	client := &http.Client{Transport: transport}
	cleanup := func() {
		transport.CloseIdleConnections()
		dev.Close()
	}
	return client, cleanup, nil
}
