package session

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cccteam/ccc/tracer"
	"github.com/cccteam/httpio"
	"github.com/cccteam/session/internal/sessioncore"
	"github.com/cccteam/session/sessioninfo"
	"github.com/cccteam/session/sessionstorage"
	"github.com/go-playground/errors/v5"
)

// The device flow (RFC 8628) is how a command-line client obtains tokens with a
// person's approval and no password of its own: the client asks the application for
// a device authorization and shows the person a short code and the application's
// page; the person, signed in to that page as they always are, approves the client;
// the client polls the token endpoint until it receives an access token and a refresh
// token. The two public endpoints speak the RFC's wire format, form-encoded requests
// or JSON and snake_case JSON answers, so a standard client library drives them; the
// approval page's handlers speak the library's usual JSON.

// The RFC's grant types and error codes.
const (
	grantDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	grantRefreshToken = "refresh_token"

	oauthAuthorizationPending = "authorization_pending"
	oauthSlowDown             = "slow_down"
	oauthAccessDenied         = "access_denied"
	oauthExpiredToken         = "expired_token"
	oauthInvalidGrant         = "invalid_grant"
	oauthInvalidRequest       = "invalid_request"
	oauthUnsupportedGrant     = "unsupported_grant_type"

	// grantBodyLimit bounds a grant request's body.
	grantBodyLimit = 1 << 16
)

// DeviceHandlers are the HTTP handlers of the device flow.
type DeviceHandlers struct {
	authorize, token, lookup, approve, deny http.HandlerFunc
}

// Authorize is the device authorization endpoint (RFC 8628, 3.1): the client posts
// client_id and outlet, form-encoded or as JSON, and is answered {"device_code",
// "user_code", "verification_uri", "verification_uri_complete", "expires_in",
// "interval"}. An outlet that is not registered, or a missing client id, is 400
// {"error": "invalid_request", "error_description"}. Route it outside
// ValidateSession and ValidateXSRFToken: the client has no session.
func (h *DeviceHandlers) Authorize() http.HandlerFunc { return h.authorize }

// Token is the token endpoint (RFC 8628, 3.4; RFC 6749, 5): the client posts
// grant_type with device_code, or grant_type=refresh_token with refresh_token, and is
// answered {"access_token", "token_type": "Bearer", "expires_in", "refresh_token"},
// or 400 {"error", "error_description"} with the RFC's codes: authorization_pending
// and slow_down while the person has not decided, access_denied, expired_token,
// invalid_grant for an unknown, redeemed, rotated or revoked token, and
// unsupported_grant_type. Route it outside ValidateSession and ValidateXSRFToken.
func (h *DeviceHandlers) Token() http.HandlerFunc { return h.token }

// Lookup answers the approval page's question about the code the person typed,
// ?userCode=, with {"clientId", "outlet", "expiresAt"} while the authorization waits,
// and 404 otherwise. Route it behind ValidateSession.
func (h *DeviceHandlers) Lookup() http.HandlerFunc { return h.lookup }

// Approve accepts {"userCode"} from the signed-in person and approves the client as
// them; the client's next poll receives its tokens. A code that names no pending
// authorization is 404. Route it behind ValidateSession and ValidateXSRFToken.
func (h *DeviceHandlers) Approve() http.HandlerFunc { return h.approve }

// Deny accepts {"userCode"} from the signed-in person and denies the client. A code
// that names no pending authorization is 404. Route it behind ValidateSession and
// ValidateXSRFToken.
func (h *DeviceHandlers) Deny() http.HandlerFunc { return h.deny }

// Device returns the device flow's handlers.
func (a *Auth[S, U, Tx]) Device() *DeviceHandlers {
	return &DeviceHandlers{
		authorize: a.serving(a.deviceAuthorize()),
		token:     a.serving(a.deviceToken()),
		lookup:    a.serving(a.deviceLookup()),
		approve:   a.serving(a.deviceDecide(true)),
		deny:      a.serving(a.deviceDecide(false)),
	}
}

// decodeGrant reads a request to the two public endpoints: form-encoded, as the RFC
// says, or JSON, as the rest of the library speaks.
func decodeGrant(r *http.Request) (map[string]string, error) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			return nil, httpio.NewBadRequestMessageWithError(err, "the request is not form-encoded")
		}
		fields := make(map[string]string, len(r.PostForm))
		for k := range r.PostForm {
			fields[k] = r.PostForm.Get(k)
		}

		return fields, nil
	}
	var fields map[string]string
	if err := json.NewDecoder(io.LimitReader(r.Body, grantBodyLimit)).Decode(&fields); err != nil {
		return nil, httpio.NewBadRequestMessageWithError(err, "the request is not JSON")
	}

	return fields, nil
}

// oauthError is the RFC's error answer.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// writeOAuth writes an answer of the two public endpoints, which are never cached
// (RFC 6749, 5.1).
func writeOAuth(w http.ResponseWriter, status int, body any) error {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := httpio.NewEncoder(w).StatusCodeWithBody(status, body); err != nil {
		return errors.Wrap(err, "httpio.Encoder.StatusCodeWithBody()")
	}

	return nil
}

// writeOAuthError writes the RFC's 400 for code.
func writeOAuthError(w http.ResponseWriter, code, description string) error {
	return writeOAuth(w, http.StatusBadRequest, oauthError{Error: code, Description: description})
}

// deviceAuthorizationResponse is the device authorization endpoint's answer.
type deviceAuthorizationResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// deviceAuthorize is Device().Authorize().
func (a *Auth[S, U, Tx]) deviceAuthorize() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		fields, err := decodeGrant(r)
		if err != nil {
			return writeOAuthError(w, oauthInvalidRequest, httpio.Message(err))
		}
		auth, err := a.API().StartDeviceAuthorization(ctx, &DeviceAuthorizationRequest{ClientID: fields["client_id"], Outlet: fields["outlet"]})
		if err != nil {
			if httpio.HasBadRequest(err) {
				return writeOAuthError(w, oauthInvalidRequest, httpio.Message(err))
			}

			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return writeOAuth(w, http.StatusOK, deviceAuthorizationResponse{
			DeviceCode: auth.DeviceCode, UserCode: auth.UserCode, VerificationURI: auth.VerificationURI, VerificationURIComplete: auth.VerificationURIComplete,
			ExpiresIn: int(auth.ExpiresIn / time.Second), Interval: int(auth.Interval / time.Second),
		})
	})
}

// tokenResponse is the token endpoint's answer (RFC 6749, 5.1).
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

// deviceToken is Device().Token().
func (a *Auth[S, U, Tx]) deviceToken() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		fields, err := decodeGrant(r)
		if err != nil {
			return writeOAuthError(w, oauthInvalidRequest, httpio.Message(err))
		}
		var pair *TokenPair
		switch fields["grant_type"] {
		case grantDeviceCode:
			pair, err = a.redeemDeviceGrant(ctx, w, fields["device_code"])
		case grantRefreshToken:
			pair, err = a.refreshGrant(ctx, w, fields["refresh_token"])
		default:
			return writeOAuthError(w, oauthUnsupportedGrant, "grant_type is "+grantDeviceCode+" or "+grantRefreshToken)
		}
		if err != nil || pair == nil {
			return err
		}

		return writeOAuth(w, http.StatusOK, tokenResponse{AccessToken: pair.AccessToken, TokenType: "Bearer", ExpiresIn: int(pair.ExpiresIn / time.Second), RefreshToken: pair.RefreshToken})
	})
}

// redeemDeviceGrant answers a device_code grant: the pair, or the RFC's error written
// and no pair.
func (a *Auth[S, U, Tx]) redeemDeviceGrant(ctx context.Context, w http.ResponseWriter, deviceCode string) (*TokenPair, error) {
	if deviceCode == "" {
		return nil, writeOAuthError(w, oauthInvalidRequest, "device_code is required")
	}
	pair, status, err := a.API().RedeemDeviceCode(ctx, deviceCode)
	if err != nil {
		if httpio.HasNotFound(err) {
			return nil, writeOAuthError(w, oauthInvalidGrant, "the device code is unknown or was redeemed")
		}

		return nil, writeClientMessage(ctx, w, err)
	}
	switch status {
	case sessionstorage.DeviceApproved:
		return pair, nil
	case sessionstorage.DevicePending:
		return nil, writeOAuthError(w, oauthAuthorizationPending, "the person has not decided yet")
	case sessionstorage.DeviceSlowDown:
		return nil, writeOAuthError(w, oauthSlowDown, "poll less often")
	case sessionstorage.DeviceDenied:
		return nil, writeOAuthError(w, oauthAccessDenied, "the person denied the request")
	case sessionstorage.DeviceExpired:
		return nil, writeOAuthError(w, oauthExpiredToken, "the device code expired; start again")
	default:
		return nil, errors.Newf("unknown device code status %q", status)
	}
}

// refreshGrant answers a refresh_token grant: the pair, or the RFC's error written
// and no pair.
func (a *Auth[S, U, Tx]) refreshGrant(ctx context.Context, w http.ResponseWriter, refreshToken string) (*TokenPair, error) {
	if refreshToken == "" {
		return nil, writeOAuthError(w, oauthInvalidRequest, "refresh_token is required")
	}
	pair, err := a.API().RefreshTokens(ctx, refreshToken)
	if err != nil {
		if httpio.HasNotFound(err) || httpio.HasUnauthorized(err) {
			return nil, writeOAuthError(w, oauthInvalidGrant, "the refresh token is not valid; sign in again")
		}

		return nil, writeClientMessage(ctx, w, err)
	}

	return pair, nil
}

// userCodeRequest is a request that names a user code.
type userCodeRequest struct {
	UserCode string `json:"userCode"`
}

var userCodeDecoder = sessioncore.NewDecoder[userCodeRequest]()

// deviceView is what the approval page is told about a pending authorization.
type deviceView struct {
	ClientID  string    `json:"clientId"`
	Outlet    string    `json:"outlet"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// deviceLookup is Device().Lookup().
func (a *Auth[S, U, Tx]) deviceLookup() http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		code, err := a.API().PendingDevice(ctx, r.URL.Query().Get(userCodeParam))
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(deviceView{ClientID: code.ClientID, Outlet: code.Outlet, ExpiresAt: code.ExpiresAt})
	})
}

// deviceDecide is Device().Approve() when approve is set, else Device().Deny().
func (a *Auth[S, U, Tx]) deviceDecide(approve bool) http.HandlerFunc {
	return a.baseSession.Handle(func(w http.ResponseWriter, r *http.Request) error {
		ctx, span := tracer.Start(r.Context())
		defer span.End()

		ctx, err := a.validateRequest(ctx)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		req, err := userCodeDecoder.Decode(r)
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}
		if approve {
			err = a.API().ApproveDevice(ctx, sessioninfo.UserFromCtx(ctx).ID, req.UserCode)
		} else {
			err = a.API().DenyDevice(ctx, req.UserCode)
		}
		if err != nil {
			return httpio.NewEncoder(w).ClientMessage(ctx, err)
		}

		return httpio.NewEncoder(w).Ok(struct{}{})
	})
}

// writeClientMessage answers err as the client message, and reports a failure to
// write it.
func writeClientMessage(ctx context.Context, w http.ResponseWriter, err error) error {
	if werr := httpio.NewEncoder(w).ClientMessage(ctx, err); werr != nil {
		return errors.Wrap(werr, "httpio.Encoder.ClientMessage()")
	}

	return nil
}
