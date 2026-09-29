package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func testWireGuardConfig() string {
	private := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	public := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	preshared := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	return "[Interface]\n" +
		"PrivateKey = " + private + " # private key\n" +
		"Address = 10.0.0.2/32, fd00::2/128\n" +
		"DNS = 10.0.0.1, fd00::1\n" +
		"MTU = 1380\n" +
		"ListenPort = 51820\n\n" +
		"[Peer]\n" +
		"PublicKey = " + public + "\n" +
		"PresharedKey = " + preshared + "\n" +
		"AllowedIPs = 0.0.0.0/0, ::/0\n" +
		"Endpoint = vpn.example:51820\n" +
		"PersistentKeepalive = 25\n"
}

func TestParseWireGuardConfig(t *testing.T) {
	cfg, err := parseWireGuardConfig([]byte(testWireGuardConfig()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.mtu != 1380 || cfg.listen != 51820 || cfg.keepalive != 25 || cfg.endpoint != "vpn.example:51820" {
		t.Fatalf("parsed WireGuard settings: mtu=%d listen=%d keepalive=%d endpoint=%q", cfg.mtu, cfg.listen, cfg.keepalive, cfg.endpoint)
	}
	if len(cfg.addresses) != 2 || len(cfg.dns) != 2 || len(cfg.allowed) != 2 {
		t.Fatalf("parsed address counts: addresses=%v dns=%v allowed=%v", cfg.addresses, cfg.dns, cfg.allowed)
	}
	ipc := cfg.ipcConfig()
	for _, want := range []string{
		"private_key=" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		"public_key=" + hex.EncodeToString(bytes.Repeat([]byte{2}, 32)),
		"preshared_key=" + hex.EncodeToString(bytes.Repeat([]byte{3}, 32)),
		"allowed_ip=0.0.0.0/0",
		"allowed_ip=::/0",
		"endpoint=vpn.example:51820",
		"persistent_keepalive_interval=25",
	} {
		if !strings.Contains(ipc, want) {
			t.Fatalf("device config missing %q", want)
		}
	}
}

func TestParseWireGuardConfigRejectsUnsafeOrIncompleteRoutes(t *testing.T) {
	base := testWireGuardConfig()
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{"split route", strings.Replace(base, "0.0.0.0/0, ::/0", "10.0.0.0/24", 1), "default route"},
		{"missing DNS", strings.Replace(base, "DNS = 10.0.0.1, fd00::1\n", "", 1), "DNS"},
		{"unsupported host hook", strings.Replace(base, "MTU = 1380", "PostUp = echo hello", 1), "unsupported"},
		{"second peer", base + "[Peer]\n", "only one"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseWireGuardConfig([]byte(tc.config))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseWireGuardConfig() error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParseWireGuardConfigFiltersUnroutedFamily(t *testing.T) {
	data := strings.Replace(testWireGuardConfig(), "0.0.0.0/0, ::/0", "0.0.0.0/0", 1)
	cfg, err := parseWireGuardConfig([]byte(data))
	if err != nil || len(cfg.addresses) != 1 || len(cfg.dns) != 1 || !cfg.addresses[0].Is4() || !cfg.dns[0].Is4() {
		t.Fatalf("partially routed families: addresses=%v dns=%v err=%v", cfg.addresses, cfg.dns, err)
	}
}

func TestParseWireGuardConfigDoesNotExposeBadKey(t *testing.T) {
	const badKey = "not-a-private-key"
	data := strings.Replace(testWireGuardConfig(), "PrivateKey = "+base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), "PrivateKey = "+badKey, 1)
	_, err := parseWireGuardConfig([]byte(data))
	if err == nil || strings.Contains(err.Error(), badKey) {
		t.Fatalf("invalid private key error should not contain key material: %v", err)
	}
}
