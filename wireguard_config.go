package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// wireGuardConfig contains only the wg-quick fields needed by the in-process
// tunnel. It never executes hooks or changes the host's network configuration.
type wireGuardConfig struct {
	addresses []netip.Addr
	dns       []netip.Addr
	mtu       int
	private   string
	public    string
	preshared string
	endpoint  string
	allowed   []netip.Prefix
	keepalive int
	listen    int
}

// parseWireGuardConfig accepts a single-peer wg-quick config with a full-tunnel
// route. A split route cannot guarantee that Crunchyroll and CDN traffic uses
// the requested VPN, so it is rejected rather than silently bypassing it.
func parseWireGuardConfig(data []byte) (wireGuardConfig, error) {
	cfg := wireGuardConfig{mtu: 1420}
	section := ""
	interfaceCount := 0
	peerCount := 0
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for line := 1; scanner.Scan(); line++ {
		text := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") {
			section = strings.ToLower(strings.TrimSpace(text[1 : len(text)-1]))
			switch section {
			case "interface":
				interfaceCount++
				if interfaceCount > 1 || peerCount != 0 {
					return cfg, fmt.Errorf("line %d: exactly one [Interface] must precede [Peer]", line)
				}
			case "peer":
				if interfaceCount != 1 {
					return cfg, fmt.Errorf("line %d: [Peer] must follow [Interface]", line)
				}
				peerCount++
				if peerCount > 1 {
					return cfg, fmt.Errorf("line %d: only one [Peer] is supported", line)
				}
			default:
				return cfg, fmt.Errorf("line %d: unsupported section", line)
			}
			continue
		}
		key, value, ok := strings.Cut(text, "=")
		if !ok || section == "" {
			return cfg, fmt.Errorf("line %d: expected a setting inside [Interface] or [Peer]", line)
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		var err error
		switch section + "." + key {
		case "interface.privatekey":
			cfg.private, err = wireGuardKey(value)
		case "interface.address":
			for _, field := range strings.Split(value, ",") {
				address := strings.TrimSpace(field)
				prefix, prefixErr := netip.ParsePrefix(address)
				if prefixErr == nil {
					cfg.addresses = append(cfg.addresses, prefix.Addr())
					continue
				}
				ip, addrErr := netip.ParseAddr(address)
				if addrErr != nil {
					err = fmt.Errorf("invalid address")
					break
				}
				cfg.addresses = append(cfg.addresses, ip)
			}
		case "interface.dns":
			for _, field := range strings.Split(value, ",") {
				ip, parseErr := netip.ParseAddr(strings.TrimSpace(field))
				if parseErr != nil {
					err = fmt.Errorf("DNS must contain IP addresses")
					break
				}
				cfg.dns = append(cfg.dns, ip)
			}
		case "interface.mtu":
			cfg.mtu, err = strconv.Atoi(value)
			if err == nil && (cfg.mtu < 576 || cfg.mtu > 9000) {
				err = fmt.Errorf("MTU must be between 576 and 9000")
			}
		case "interface.listenport":
			if value == "0" {
				cfg.listen = 0
			} else {
				cfg.listen, err = parseWireGuardPort(value)
			}
		case "peer.publickey":
			cfg.public, err = wireGuardKey(value)
		case "peer.presharedkey":
			cfg.preshared, err = wireGuardKey(value)
		case "peer.endpoint":
			var port string
			var host string
			host, port, err = net.SplitHostPort(value)
			if err == nil && host == "" {
				err = fmt.Errorf("endpoint host is empty")
			}
			if err == nil {
				_, err = parseWireGuardPort(port)
			}
			if err == nil {
				cfg.endpoint = value
			}
		case "peer.allowedips":
			for _, field := range strings.Split(value, ",") {
				prefix, parseErr := netip.ParsePrefix(strings.TrimSpace(field))
				if parseErr != nil {
					err = fmt.Errorf("invalid AllowedIPs route")
					break
				}
				cfg.allowed = append(cfg.allowed, prefix.Masked())
			}
		case "peer.persistentkeepalive":
			if strings.EqualFold(value, "off") {
				cfg.keepalive = 0
			} else {
				cfg.keepalive, err = strconv.Atoi(value)
				if err == nil && (cfg.keepalive < 0 || cfg.keepalive > 65535) {
					err = fmt.Errorf("keepalive must be between 0 and 65535 seconds")
				}
			}
		default:
			return cfg, fmt.Errorf("line %d: unsupported %s setting %q", line, section, key)
		}
		if err != nil {
			// Key values are secrets; keep them out of diagnostics.
			return cfg, fmt.Errorf("line %d: invalid %s setting %q: %w", line, section, key, err)
		}
	}
	if err := scanner.Err(); err != nil {
		return cfg, fmt.Errorf("reading WireGuard config: %w", err)
	}
	if cfg.private == "" || cfg.public == "" || cfg.endpoint == "" || len(cfg.addresses) == 0 || len(cfg.dns) == 0 || len(cfg.allowed) == 0 || interfaceCount != 1 || peerCount != 1 {
		return cfg, fmt.Errorf("WireGuard config requires one peer, PrivateKey, Address, DNS, PublicKey, Endpoint, and AllowedIPs")
	}
	var routeV4, routeV6 bool
	for _, route := range cfg.allowed {
		if route.Bits() == 0 {
			if route.Addr().Is4() {
				routeV4 = true
			} else {
				routeV6 = true
			}
		}
	}
	var addressV4, addressV6 bool
	for _, address := range cfg.addresses {
		if address.Is4() {
			addressV4 = true
		} else {
			addressV6 = true
		}
	}
	if (!addressV4 || !routeV4) && (!addressV6 || !routeV6) {
		return cfg, fmt.Errorf("AllowedIPs needs a default route (0.0.0.0/0 or ::/0) matching an interface Address")
	}
	// Keep only families that are fully routed; this prevents a resolver from
	// picking an address family that would escape the peer's AllowedIPs.
	addresses := cfg.addresses[:0]
	for _, address := range cfg.addresses {
		if (address.Is4() && routeV4) || (address.Is6() && routeV6) {
			addresses = append(addresses, address)
		}
	}
	cfg.addresses = addresses
	if cfg.mtu < 1280 {
		for _, address := range cfg.addresses {
			if address.Is6() {
				return cfg, fmt.Errorf("IPv6 WireGuard addresses require an MTU of at least 1280")
			}
		}
	}
	dns := cfg.dns[:0]
	for _, address := range cfg.dns {
		if (address.Is4() && routeV4 && addressV4) || (address.Is6() && routeV6 && addressV6) {
			dns = append(dns, address)
		}
	}
	cfg.dns = dns
	if len(cfg.dns) == 0 {
		return cfg, fmt.Errorf("DNS needs an IP address in a fully routed address family")
	}
	return cfg, nil
}

func wireGuardKey(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return "", fmt.Errorf("expected a 32-byte base64 WireGuard key")
	}
	return hex.EncodeToString(decoded), nil
}

func parseWireGuardPort(value string) (int, error) {
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return port, nil
}

// ipcConfig converts the user-facing base64 config to WireGuard's hex-key UAPI.
// Never print the returned string: it contains the private and preshared keys.
func (cfg wireGuardConfig) ipcConfig() string {
	var out strings.Builder
	fmt.Fprintf(&out, "private_key=%s\n", cfg.private)
	if cfg.listen != 0 {
		fmt.Fprintf(&out, "listen_port=%d\n", cfg.listen)
	}
	fmt.Fprintf(&out, "public_key=%s\n", cfg.public)
	if cfg.preshared != "" {
		fmt.Fprintf(&out, "preshared_key=%s\n", cfg.preshared)
	}
	fmt.Fprintf(&out, "endpoint=%s\n", cfg.endpoint)
	for _, route := range cfg.allowed {
		fmt.Fprintf(&out, "allowed_ip=%s\n", route)
	}
	if cfg.keepalive != 0 {
		fmt.Fprintf(&out, "persistent_keepalive_interval=%d\n", cfg.keepalive)
	}
	return out.String()
}
