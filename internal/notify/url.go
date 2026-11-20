package notify

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"

	"agent-manager/internal/fetch"
)

// MaxURLLength bounds a subscription's URL.
const MaxURLLength = 2048

// ErrInvalidURL marks a URL a subscription may not deliver to.
var ErrInvalidURL = errors.New("invalid webhook url")

// ValidateURL is the creation-time half of the SSRF control: https only, no
// credentials, no fragment, and no host that is a non-public IP literal or a
// localhost name. The delivery-time half is the outbound client, which
// re-checks every address the name resolves to.
func ValidateURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > MaxURLLength {
		return nil, fmt.Errorf("%w: a url of 1 to %d characters is required", ErrInvalidURL, MaxURLLength)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: it does not parse", ErrInvalidURL)
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	switch {
	case u.Scheme != "https":
		return nil, fmt.Errorf("%w: only https is accepted", ErrInvalidURL)
	case u.User != nil:
		return nil, fmt.Errorf("%w: it carries credentials; put them in the path or a query parameter the receiver checks", ErrInvalidURL)
	case u.Fragment != "" || strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%w: it has a fragment", ErrInvalidURL)
	case host == "":
		return nil, fmt.Errorf("%w: it has no host", ErrInvalidURL)
	case host == "localhost" || strings.HasSuffix(host, ".localhost"):
		return nil, fmt.Errorf("%w: localhost is not reachable from the hub", ErrInvalidURL)
	}
	if ip := net.ParseIP(host); ip != nil {
		if reason := fetch.ReservedReason(ip); reason != "" {
			return nil, fmt.Errorf("%w: %s", ErrInvalidURL, reason)
		}
	}
	return u, nil
}

// RedactedHost is what an audit row or a log line may say about a URL: chat
// webhooks carry their credential in the path, so nothing past the host.
func RedactedHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
