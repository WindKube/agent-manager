package fetch

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// This file holds the SSRF policy, owned here rather than delegated to a
// library. Everything below is a pure decision over a URL or an address: no
// I/O, so the classification is testable on its own and cannot be bypassed
// by a code path that forgets to call the network wrapper.

var (
	allowedSchemes = []string{"http", "https"}
	// Ports outside this list are refused even on a public address. A public host
	// answering on 6379 or 11211 is a request smuggling target, not a package
	// source. Operators widen this per-address through Options.Allowlist.
	defaultPorts = []int{80, 443}
)

// reservedNets is every block that must not be reachable from a user-supplied
// URL. The documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
// are in here deliberately: they are not routable, so a URL pointing at one is
// either a mistake or a probe.
var reservedNets = mustCIDRs(
	// IPv4 — RFC 6890 special-purpose registry.
	"0.0.0.0/8",          // this host on this network
	"10.0.0.0/8",         // private
	"100.64.0.0/10",      // carrier-grade NAT
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link-local, and therefore cloud metadata
	"172.16.0.0/12",      // private
	"192.0.0.0/24",       // IETF protocol assignments
	"192.0.2.0/24",       // TEST-NET-1
	"192.31.196.0/24",    // AS112-v4
	"192.52.193.0/24",    // AMT
	"192.88.99.0/24",     // deprecated 6to4 relay anycast
	"192.168.0.0/16",     // private
	"192.175.48.0/24",    // direct delegation AS112
	"198.18.0.0/15",      // benchmarking
	"198.51.100.0/24",    // TEST-NET-2
	"203.0.113.0/24",     // TEST-NET-3
	"224.0.0.0/4",        // multicast
	"240.0.0.0/4",        // reserved
	"255.255.255.255/32", // broadcast
	// IPv6 — IANA special-purpose registry.
	"::/128",  // unspecified
	"::1/128", // loopback
	// ::a.b.c.d and ::ffff:0:a.b.c.d embed an IPv4 address without being
	// IPv4-mapped, so To4 does not normalise them and every Is* predicate below
	// answers false. Both are deprecated translation prefixes: refuse the
	// spelling rather than depend on the host having no route for it.
	"::/96",             // deprecated IPv4-compatible
	"::ffff:0:0:0/96",   // deprecated IPv4-translated (RFC 2765)
	"64:ff9b::/96",      // NAT64, embeds arbitrary IPv4
	"64:ff9b:1::/48",    // local-use NAT64
	"2620:4f:8000::/48", // direct delegation AS112
	"100::/64",          // discard-only
	"2001::/23",         // IETF protocol assignments, includes Teredo
	"2001:2::/48",       // benchmarking
	"2001:db8::/32",     // documentation
	"2002::/16",         // 6to4, embeds arbitrary IPv4
	"3fff::/20",         // documentation
	"5f00::/16",         // SRv6 SIDs
	"fc00::/7",          // unique local
	"fe80::/10",         // link-local
	"ff00::/8",          // multicast
)

type policy struct {
	allow allowlist
}

// checkURL validates everything decidable without resolving the host.
func (p policy) checkURL(u *url.URL) error {
	target := u.Redacted()

	// Scheme first, so file:// and gopher:// report the reason a reader
	// expects rather than "empty host".
	if !slices.Contains(allowedSchemes, strings.ToLower(u.Scheme)) {
		return &BlockedError{Target: target, Reason: fmt.Sprintf("scheme %q is not http or https", u.Scheme)}
	}
	if u.User != nil {
		return &BlockedError{Target: target, Reason: "url carries credentials"}
	}
	if u.Hostname() == "" {
		return &BlockedError{Target: target, Reason: "url has no host"}
	}
	return nil
}

// checkAddr is the single decision point for "may this address be connected to".
// Both the pre-flight check and the dialer call it, so there is one rule and one
// error message.
func (p policy) checkAddr(ip net.IP, port int) error {
	if v4 := ip.To4(); v4 != nil {
		// ::ffff:127.0.0.1 is 127.0.0.1. Normalise before classifying so the
		// mapped form cannot walk past an IPv4-only table.
		ip = v4
	}
	target := net.JoinHostPort(ip.String(), strconv.Itoa(port))

	if p.allow.permits(ip, port) {
		return nil
	}
	if reason := reservedReason(ip); reason != "" {
		return &BlockedError{Target: target, Reason: reason}
	}
	if !slices.Contains(defaultPorts, port) {
		return &BlockedError{Target: target, Reason: fmt.Sprintf("port %d is not 80 or 443 and is not allowlisted", port)}
	}
	return nil
}

func (p policy) checkDialAddr(address string) error {
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return &BlockedError{Target: address, Reason: "address is not host:port"}
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// The dialer is only ever handed a literal address by dialContext. A name
		// here means someone bypassed the resolution step.
		return &BlockedError{Target: address, Reason: "dial address is not a literal ip"}
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return &BlockedError{Target: address, Reason: "port is not numeric"}
	}
	return p.checkAddr(ip, port)
}

// reservedReason returns why ip is not a public address, or "" if it is one.
//
// Returning "" means "connect to this", so anything the classifiers below cannot
// reason about has to be refused here rather than fall out of the bottom. A
// net.IP of any other length answers false to every Is* predicate and is
// contained by no CIDR, so without this length check a malformed address would
// be reported as public.
func reservedReason(ip net.IP) string {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return "address is not a valid ip"
	}
	switch {
	case ip.IsUnspecified():
		return "unspecified address"
	case ip.IsLoopback():
		return "loopback address"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local address"
	case ip.IsInterfaceLocalMulticast(), ip.IsMulticast():
		return "multicast address"
	case ip.IsPrivate():
		return "private address"
	}
	for _, n := range reservedNets {
		if n.Contains(ip) {
			return "reserved, non-public address in " + n.String()
		}
	}
	return ""
}

/* allowlist */

type allowEntry struct {
	net *net.IPNet
	// port 0 means the entry permits any port on those addresses.
	port int
}

type allowlist []allowEntry

func parseAllowlist(entries []string) (allowlist, error) {
	var out allowlist
	for _, raw := range entries {
		e := strings.TrimSpace(raw)
		if e == "" {
			continue
		}
		entry, err := parseAllowEntry(e)
		if err != nil {
			return nil, err
		}
		out = append(out, entry)
	}
	return out, nil
}

func parseAllowEntry(e string) (allowEntry, error) {
	if strings.Contains(e, "/") {
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return allowEntry{}, fmt.Errorf("outbound allowlist entry %q is not a valid cidr: %w", e, err)
		}
		return allowEntry{net: n}, nil
	}
	if ip := net.ParseIP(e); ip != nil {
		return allowEntry{net: hostNet(ip)}, nil
	}

	host, portStr, err := net.SplitHostPort(e)
	if err != nil {
		return allowEntry{}, fmt.Errorf("outbound allowlist entry %q must be an ip, ip:port or cidr: %w", e, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return allowEntry{}, fmt.Errorf(
			"outbound allowlist entry %q must be an ip, ip:port or cidr; a hostname is not accepted because a name can be made to resolve to a private address", e)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return allowEntry{}, fmt.Errorf("outbound allowlist entry %q has an out-of-range port", e)
	}
	return allowEntry{net: hostNet(ip), port: port}, nil
}

func hostNet(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func (a allowlist) permits(ip net.IP, port int) bool {
	for _, e := range a {
		if e.port != 0 && e.port != port {
			continue
		}
		if e.net.Contains(ip) {
			return true
		}
	}
	return false
}

func mustCIDRs(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			panic("fetch: bad reserved cidr " + c + ": " + err.Error())
		}
		out = append(out, n)
	}
	return out
}
