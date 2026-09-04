package hub

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"agent-manager/internal/web/view"
)

// The Connect-the-CLI screen's door to the api, through the generated client
// and nothing else.

// The three distinguishable device-code refusals. There is no separate
// wrong-identity case: device_authorization binds a host, never a requester
// identity, so the api answers that exactly like ErrDeviceCodeDecided.
var (
	ErrDeviceCodeUnknown = errors.New("no such device authorisation")
	ErrDeviceCodeExpired = errors.New("this code has expired")
	ErrDeviceCodeDecided = errors.New("this code has already been decided")
)

// LookupDeviceCode reads GET /v1/device/authorizations/{user_code}.
func (c *Client) LookupDeviceCode(ctx context.Context, userCode string) (view.PendingDeviceAuthorization, error) {
	resp, err := c.api.LookupDeviceCodeWithResponse(ctx, userCode)
	if err != nil {
		return view.PendingDeviceAuthorization{}, fmt.Errorf("look up device code: %w", err)
	}
	if resp.JSON200 == nil {
		return view.PendingDeviceAuthorization{}, fmt.Errorf("look up device code: %w",
			deviceCodeError(resp.HTTPResponse, resp.Body))
	}
	return view.PendingDeviceAuthorization{
		RequestingHost: resp.JSON200.RequestingHost,
		ExpiresAt:      c.now().Add(time.Duration(resp.JSON200.ExpiresIn) * time.Second),
	}, nil
}

// ApproveDeviceCode posts POST /v1/device/authorizations/{user_code}/approve and
// returns the host that was approved.
func (c *Client) ApproveDeviceCode(ctx context.Context, userCode string) (string, error) {
	resp, err := c.api.ApproveDeviceCodeWithResponse(ctx, userCode)
	if err != nil {
		return "", fmt.Errorf("approve device code: %w", err)
	}
	if resp.JSON200 == nil {
		return "", fmt.Errorf("approve device code: %w", deviceCodeError(resp.HTTPResponse, resp.Body))
	}
	return resp.JSON200.RequestingHost, nil
}

// deviceCodeError adds the three device-code refusals to statusError, which
// already turns a 401 into view.ErrSignedOut.
func deviceCodeError(resp *http.Response, body []byte) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusNotFound:
			return ErrDeviceCodeUnknown
		case http.StatusGone:
			return ErrDeviceCodeExpired
		case http.StatusConflict:
			return ErrDeviceCodeDecided
		}
	}
	return statusError(resp, body)
}
