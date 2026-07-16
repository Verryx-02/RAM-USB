// forward.go implements EH-F-07 (forward an already-validated request to
// Security-Switch over mTLS), EH-F-08 (relay Security-Switch's response
// back to the client unchanged), and EH-F-09 (map a failure of the call
// itself - not a response Security-Switch actually sent - to HTTP
// 500/502/503).
package httpapi

import (
	"errors"
	"net/http"

	apperrors "github.com/Verryx-02/RAM-USB/pkg/errors"
	"github.com/Verryx-02/RAM-USB/pkg/validation"
	"github.com/Verryx-02/RAM-USB/services/entry-hub/internal/securityswitch"
)

// forwardRegister implements EH-F-07/EH-F-08/EH-F-09 for Register: forward
// req to Security-Switch and either relay its response unchanged, or map
// a call failure to a sanitized error response.
func (h *Handler) forwardRegister(w http.ResponseWriter, r *http.Request, req validation.RegisterRequest, isError *bool) {
	result := h.SecuritySwitch.Register(r.Context(), req)
	h.relay(w, result, isError)
}

// forwardLogin implements EH-F-07/EH-F-08/EH-F-09 for Login: forward req
// to Security-Switch and either relay its response unchanged, or map a
// call failure to a sanitized error response.
func (h *Handler) forwardLogin(w http.ResponseWriter, r *http.Request, req validation.LoginRequest, isError *bool) {
	result := h.SecuritySwitch.Login(r.Context(), req)
	h.relay(w, result, isError)
}

// relay implements EH-F-08's "forward Security-Switch's response back to
// the user" for a completed call, and EH-F-09's error mapping for a call
// that did not complete.
func (h *Handler) relay(w http.ResponseWriter, result securityswitch.Result, isError *bool) {
	if result.Err != nil {
		*isError = true
		h.logger().Error("forward to security-switch failed", "error", result.Err)
		writeAppError(w, mapSecuritySwitchError(result.Err))
		return
	}

	if result.StatusCode >= http.StatusBadRequest {
		*isError = true
	}

	h.logger().Info("security-switch response relayed", "status", result.StatusCode)
	writeForwardedResponse(w, result)
}

// writeForwardedResponse writes Security-Switch's own response back to
// the client completely unchanged (EH-F-08): the exact status code, the
// exact Content-Type (falling back to application/json if Security-Switch
// did not set one - every response Security-Switch's own httpapi package
// writes carries application/json), and the exact body bytes, with no
// re-encoding.
func writeForwardedResponse(w http.ResponseWriter, result securityswitch.Result) {
	contentType := result.ContentType
	if contentType == "" {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(result.StatusCode)
	_, _ = w.Write(result.Body)
}

// mapSecuritySwitchError implements EH-F-09 for a failed call to
// Security-Switch (not a response Security-Switch itself sent, which is
// always relayed unchanged by writeForwardedResponse instead): a timeout
// maps to 503, any other unreachable failure to 502, falling back to 500
// for anything else. EH-F-09's fixed status set (400/401/500/502/503)
// deliberately differs from Security-Switch's own SS-F-06 set
// (400/401/403/500/502/504): Entry-Hub never constructs a 403 (it has no
// downstream "explicit refusal" case of its own, unlike Security-Switch's
// Network-Manager grant denial) and uses 503, not 504, for a timed-out
// downstream call - both are the SRS's own literal per-component
// choices, not values to reconcile with Security-Switch's set.
func mapSecuritySwitchError(err error) *apperrors.AppError {
	switch {
	case errors.Is(err, securityswitch.ErrSecuritySwitchTimeout):
		return apperrors.NewServiceUnavailable(err)
	case errors.Is(err, securityswitch.ErrSecuritySwitchUnreachable):
		return apperrors.NewBadGateway(err)
	default:
		return apperrors.NewInternal(err)
	}
}
