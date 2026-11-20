package notify

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// SecretSize is the length of a signing key in bytes.
const SecretSize = 32

const secretPrefix = "whsec_"

// NewSecret returns a fresh signing key.
func NewSecret() ([]byte, error) {
	key := make([]byte, SecretSize)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate a webhook secret: %w", err)
	}
	return key, nil
}

// EncodeSecret is the key as shown to the person once: whsec_ and base64,
// the Standard Webhooks spelling, so off-the-shelf verifiers accept it.
func EncodeSecret(key []byte) string {
	return secretPrefix + base64.StdEncoding.EncodeToString(key)
}

// DecodeSecret is EncodeSecret's inverse.
func DecodeSecret(s string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, secretPrefix))
	if err != nil || len(key) == 0 {
		return nil, errors.New("not a webhook secret")
	}
	return key, nil
}

// Sign is the Webhook-Signature header value for one delivery:
// v1,base64(HMAC-SHA256(key, id.timestamp.body)).
func Sign(key []byte, id string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(id))
	mac.Write([]byte{'.'})
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Verify checks a Webhook-Signature header, which may list several
// space-separated signatures, against one delivery.
func Verify(key []byte, id string, timestamp int64, body []byte, header string) bool {
	want := Sign(key, id, timestamp, body)
	for _, candidate := range strings.Fields(header) {
		if hmac.Equal([]byte(candidate), []byte(want)) {
			return true
		}
	}
	return false
}
