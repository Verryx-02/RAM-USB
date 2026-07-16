// Package validation provides the input re-validation logic shared by every
// RAM-USB service that must independently confirm registration and login
// input is well-formed, without trusting any upstream layer's result, per
// the zero-trust/defense-in-depth requirements (RNF-SEC-02, RNF-SEC-03).
// Each component-level requirement that repeats this pattern - EH-F-04/
// EH-F-05 (Entry-Hub validates client input first), SS-F-02
// (Security-Switch re-validates independently of Entry-Hub), DV-F-02
// (Database-Vault re-validates independently of Security-Switch) - calls
// this same logic at its own boundary instead of re-implementing the check.
//
// Two kinds of checks are performed, at two different points:
//
//   - Decoding-time checks (DecodeRegisterRequest, DecodeLoginRequest):
//     payload size within a defined limit and no unexpected additional
//     JSON fields. These are properties of the raw request body, so they
//     are enforced while decoding it, before a RegisterRequest/LoginRequest
//     value even exists.
//   - Field-level checks (ValidateRegister, ValidateLogin): presence and
//     shape of each field once decoded - email format (RFC 5322), password
//     length and character-class complexity, and SSH public key
//     well-formedness.
//
// Per EH-F-04/EH-F-05, the SSH public key is only checked for well-formed
// syntax here, never for possession of the corresponding private key.
// Proof of possession happens later, at the actual SFTP connection, via
// Storage-Service's AuthorizedKeysCommand (ST-F-11).
package validation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/mail"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// maxPayloadBytes bounds the size of a registration or login JSON request
// body (EH-F-04, EH-F-05). The body carries at most an email address, a
// password, and one SSH public key line. Worst-case realistic size: a
// 254-character RFC 5322 email, a 128-character password (the maximum
// allowed by EH-F-04/EH-F-05), and an RSA-4096 authorized_keys line. The RSA
// key's wire encoding is `string "ssh-rsa"` (11 bytes) + `mpint e` (7 bytes)
// + `mpint n` (517 bytes for a 4096-bit modulus) = 535 bytes, which
// base64-encodes to 716 characters; adding the "ssh-rsa " prefix and a
// comment brings the full authorized_keys line to about 825 characters.
// Summed with JSON structural overhead, the worst-case payload is
// approximately 1278 bytes. 2048 bytes (2 KiB) gives about 1.6x headroom
// over that calculated worst case - a deliberately modest buffer, not a
// large oversized guess - while still rejecting any payload large enough to
// be a resource-exhaustion attempt rather than a legitimate request.
const maxPayloadBytes = 2048

// Sentinel errors returned by DecodeRegisterRequest, DecodeLoginRequest,
// ValidateRegister, and ValidateLogin. Callers can match on these with
// errors.Is; none of them include the offending field's value, so a caller
// that logs the error (DV-F-20) never risks writing a credential to the
// log.
var (
	ErrPayloadTooLarge      = errors.New("request payload exceeds the size limit")
	ErrUnknownField         = errors.New("request payload contains an unexpected field")
	ErrMalformedJSON        = errors.New("request payload is not valid JSON")
	ErrEmailRequired        = errors.New("email is required")
	ErrEmailInvalid         = errors.New("email is invalid")
	ErrPasswordRequired     = errors.New("password is required")
	ErrPasswordTooShort     = errors.New("password is too short")
	ErrPasswordTooLong      = errors.New("password is too long")
	ErrPasswordTooSimple    = errors.New("password does not meet complexity requirements")
	ErrSSHPublicKeyRequired = errors.New("ssh public key is required")
	ErrSSHPublicKeyInvalid  = errors.New("ssh public key is invalid")
)

// minPasswordLength, maxPasswordLength, and minPasswordCategories implement
// the password policy shared by EH-F-04 (register) and EH-F-05 (login).
const (
	minPasswordLength     = 8
	maxPasswordLength     = 128
	minPasswordCategories = 3
)

// RegisterRequest holds the fields validated for registration (UC-01):
// email, password, and SSH public key, as originally sent by the client
// (CL-F-02).
type RegisterRequest struct {
	Email        string `json:"email"`
	Password     string `json:"password"`
	SSHPublicKey string `json:"ssh_public_key"`
}

// LoginRequest holds the fields validated for login (UC-02): email and
// password, without an SSH key.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// DecodeRegisterRequest decodes a registration JSON body from r, enforcing
// the payload-size limit and unknown-field rejection required by EH-F-04
// (and re-validated independently by SS-F-02/DV-F-02). It does not check
// field presence, shape, or complexity - call ValidateRegister on the
// result for that.
func DecodeRegisterRequest(r io.Reader) (RegisterRequest, error) {
	var req RegisterRequest
	if err := decodeJSON(r, &req); err != nil {
		return RegisterRequest{}, err
	}
	return req, nil
}

// DecodeLoginRequest decodes a login JSON body from r, enforcing the
// payload-size limit and unknown-field rejection required by EH-F-05 (and
// re-validated independently by SS-F-02/DV-F-02). It does not check field
// presence or shape - call ValidateLogin on the result for that.
func DecodeLoginRequest(r io.Reader) (LoginRequest, error) {
	var req LoginRequest
	if err := decodeJSON(r, &req); err != nil {
		return LoginRequest{}, err
	}
	return req, nil
}

// decodeJSON decodes a single JSON object from r into dst, capping the
// number of bytes read at maxPayloadBytes+1 (so an oversized body is
// detected without buffering an unbounded amount of attacker-controlled
// data) and rejecting any field in the body that dst does not declare.
func decodeJSON(r io.Reader, dst any) error {
	limited := io.LimitReader(r, maxPayloadBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return ErrMalformedJSON
	}
	if len(body) > maxPayloadBytes {
		return ErrPayloadTooLarge
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return ErrUnknownField
		}
		return ErrMalformedJSON
	}
	return nil
}

// ValidateRegister checks that req is structurally valid, independently of
// any validation already performed by another layer (EH-F-04, SS-F-02,
// DV-F-02). It returns nil if req is structurally valid, or the first
// applicable sentinel error otherwise.
func ValidateRegister(req RegisterRequest) error {
	if err := validateEmail(req.Email); err != nil {
		return err
	}
	if err := validatePassword(req.Password); err != nil {
		return err
	}
	return validateSSHPublicKey(req.SSHPublicKey)
}

// ValidateLogin checks that req is structurally valid, independently of any
// validation already performed by another layer (EH-F-05, SS-F-02, DV-F-02).
// It returns nil if req is structurally valid, or the first applicable
// sentinel error otherwise.
func ValidateLogin(req LoginRequest) error {
	if err := validateEmail(req.Email); err != nil {
		return err
	}
	return validatePassword(req.Password)
}

// validateEmail checks that email is present and structurally a single
// RFC 5322 address (e.g. "local@domain"), the minimal shape shared by every
// valid email address, without enforcing any additional allow/deny policy.
func validateEmail(email string) error {
	if strings.TrimSpace(email) == "" {
		return ErrEmailRequired
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return ErrEmailInvalid
	}
	return nil
}

// validatePassword checks that a password was supplied, is between
// minPasswordLength and maxPasswordLength characters long, and draws from at
// least minPasswordCategories of the four character categories (lowercase,
// uppercase, digit, symbol), per EH-F-04/EH-F-05.
func validatePassword(password string) error {
	if password == "" {
		return ErrPasswordRequired
	}
	length := len([]rune(password))
	if length < minPasswordLength {
		return ErrPasswordTooShort
	}
	if length > maxPasswordLength {
		return ErrPasswordTooLong
	}
	if passwordCategoryCount(password) < minPasswordCategories {
		return ErrPasswordTooSimple
	}
	return nil
}

// passwordCategoryCount counts how many of the four character categories -
// lowercase letter, uppercase letter, digit, symbol (anything else) -
// appear at least once in password.
func passwordCategoryCount(password string) int {
	var hasLower, hasUpper, hasDigit, hasSymbol bool
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		default:
			hasSymbol = true
		}
	}
	count := 0
	for _, has := range []bool{hasLower, hasUpper, hasDigit, hasSymbol} {
		if has {
			count++
		}
	}
	return count
}

// validateSSHPublicKey checks that key is present and parses as a single
// well-formed OpenSSH authorized_keys line (CL-F-01/CL-F-02).
func validateSSHPublicKey(key string) error {
	if strings.TrimSpace(key) == "" {
		return ErrSSHPublicKeyRequired
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key)); err != nil {
		return ErrSSHPublicKeyInvalid
	}
	return nil
}
