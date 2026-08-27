package fetch

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

// Resolver is the name-resolution seam. *net.Resolver satisfies it. It exists
// because R10 cases 2 and 4 are statements about what a name answers with, and
// without this they cannot be tested at all.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

func (c *guardedClient) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	addrs, err := c.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, &BlockedError{Target: host, Reason: "name resolved to no addresses"}
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// dialContext is the half of the control that cannot be talked out of its
// answer. It re-resolves and re-checks at connect time, so:
//
//   - a name that answered public during checkURL and private now is refused
//     (R10 case 4 — the pre-flight answer is not evidence about this connection);
//   - every address in a rotation is checked, and one bad address refuses the
//     whole dial rather than being skipped in favour of a good one (R10 case 2);
//   - each hop of a redirect arrives here as its own dial, so the check re-runs
//     per hop rather than once per request (R10 cases 1 and 3).
//
// No connection is opened before the checks pass, which is what US1 scenario 5
// means by "refused before any connection completes".
func (c *guardedClient) dialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("dial address %q is not host:port: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, &BlockedError{Target: addr, Reason: "port is not numeric"}
	}

	ips, err := c.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if err := c.policy.checkAddr(ip, port); err != nil {
			return nil, err
		}
	}

	d := net.Dialer{
		Timeout: dialTimeout,
		// Last line of defence. Control sees the address actually handed to the
		// kernel, so a future refactor that reaches the dialer without the loop
		// above still cannot open a socket to a private address.
		Control: func(_, address string, _ syscall.RawConn) error {
			return c.policy.checkDialAddr(address)
		},
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
