package validation_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/Verryx-02/RAM-USB/pkg/validation"
)

// A syntactically valid Ed25519 authorized_keys line, reused across test
// cases that need a well-formed SSH public key.
const validSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJl6r+SEQfM50WkfR/4iZpu9NDXCBs4RwIKidjhOCbdw user@client"

// A password meeting the length (>= 8) and complexity (>= 3 of lowercase,
// uppercase, digit, symbol) policy from EH-F-04/EH-F-05, reused across test
// cases that don't specifically exercise the password policy.
const validPassword = "Str0ng!Pass"

// password128 is exactly 128 characters long ("Aa1!" repeated 32 times),
// the maximum length allowed by EH-F-04/EH-F-05, and hits all four
// character categories.
var password128 = strings.Repeat("Aa1!", 32)

// Requirement: DV-F-02
func TestValidateRegister(t *testing.T) {
	tests := []struct {
		name    string
		request validation.RegisterRequest
		wantErr error
	}{
		{
			name: "well-formed request passes",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     validPassword,
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: nil,
		},
		{
			name: "missing email is rejected",
			request: validation.RegisterRequest{
				Email:        "",
				Password:     validPassword,
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrEmailRequired,
		},
		{
			name: "email without an @ is rejected",
			request: validation.RegisterRequest{
				Email:        "not-an-email",
				Password:     validPassword,
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrEmailInvalid,
		},
		{
			name: "missing password is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     "",
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrPasswordRequired,
		},
		{
			name: "password shorter than 8 characters is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     "Sh0rt!a",
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrPasswordTooShort,
		},
		{
			name: "password with fewer than 3 character categories is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     "lowercaseonly",
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrPasswordTooSimple,
		},
		{
			name: "password with exactly 2 character categories is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     "lowercase1",
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrPasswordTooSimple,
		},
		{
			name: "password with exactly 3 character categories passes",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     "Lowercase1",
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: nil,
		},
		{
			name: "password of exactly 128 characters passes",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     password128,
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: nil,
		},
		{
			name: "password of 129 characters is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     password128 + "x",
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: validation.ErrPasswordTooLong,
		},
		{
			name: "missing SSH public key is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     validPassword,
				SSHPublicKey: "",
			},
			wantErr: validation.ErrSSHPublicKeyRequired,
		},
		{
			name: "malformed SSH public key is rejected",
			request: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     validPassword,
				SSHPublicKey: "not a valid authorized_keys line",
			},
			wantErr: validation.ErrSSHPublicKeyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validation.ValidateRegister(tt.request)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateRegister() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// Requirement: DV-F-02
func TestValidateLogin(t *testing.T) {
	tests := []struct {
		name    string
		request validation.LoginRequest
		wantErr error
	}{
		{
			name: "well-formed request passes",
			request: validation.LoginRequest{
				Email:    "user@example.com",
				Password: validPassword,
			},
			wantErr: nil,
		},
		{
			name: "missing email is rejected",
			request: validation.LoginRequest{
				Email:    "",
				Password: validPassword,
			},
			wantErr: validation.ErrEmailRequired,
		},
		{
			name: "email without an @ is rejected",
			request: validation.LoginRequest{
				Email:    "not-an-email",
				Password: validPassword,
			},
			wantErr: validation.ErrEmailInvalid,
		},
		{
			name: "missing password is rejected",
			request: validation.LoginRequest{
				Email:    "user@example.com",
				Password: "",
			},
			wantErr: validation.ErrPasswordRequired,
		},
		{
			name: "password shorter than 8 characters is rejected",
			request: validation.LoginRequest{
				Email:    "user@example.com",
				Password: "Sh0rt!a",
			},
			wantErr: validation.ErrPasswordTooShort,
		},
		{
			name: "password with fewer than 3 character categories is rejected",
			request: validation.LoginRequest{
				Email:    "user@example.com",
				Password: "lowercaseonly",
			},
			wantErr: validation.ErrPasswordTooSimple,
		},
		{
			name: "password of exactly 128 characters passes",
			request: validation.LoginRequest{
				Email:    "user@example.com",
				Password: password128,
			},
			wantErr: nil,
		},
		{
			name: "password of 129 characters is rejected",
			request: validation.LoginRequest{
				Email:    "user@example.com",
				Password: password128 + "x",
			},
			wantErr: validation.ErrPasswordTooLong,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validation.ValidateLogin(tt.request)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ValidateLogin() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// Requirement: DV-F-02
func TestDecodeRegisterRequest(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    validation.RegisterRequest
		wantErr error
	}{
		{
			name: "well-formed payload decodes",
			body: `{"email":"user@example.com","password":"` + validPassword + `","ssh_public_key":"` + validSSHPublicKey + `"}`,
			want: validation.RegisterRequest{
				Email:        "user@example.com",
				Password:     validPassword,
				SSHPublicKey: validSSHPublicKey,
			},
			wantErr: nil,
		},
		{
			name:    "unexpected additional field is rejected",
			body:    `{"email":"user@example.com","password":"` + validPassword + `","ssh_public_key":"` + validSSHPublicKey + `","is_admin":true}`,
			wantErr: validation.ErrUnknownField,
		},
		{
			name:    "malformed JSON is rejected",
			body:    `{"email":`,
			wantErr: validation.ErrMalformedJSON,
		},
		{
			name:    "payload exceeding the size limit is rejected",
			body:    `{"email":"user@example.com","password":"` + validPassword + `","ssh_public_key":"` + strings.Repeat("a", 2000) + `"}`,
			wantErr: validation.ErrPayloadTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validation.DecodeRegisterRequest(strings.NewReader(tt.body))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DecodeRegisterRequest() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got != tt.want {
				t.Fatalf("DecodeRegisterRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// Requirement: DV-F-02
func TestDecodeLoginRequest(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    validation.LoginRequest
		wantErr error
	}{
		{
			name: "well-formed payload decodes",
			body: `{"email":"user@example.com","password":"` + validPassword + `"}`,
			want: validation.LoginRequest{
				Email:    "user@example.com",
				Password: validPassword,
			},
			wantErr: nil,
		},
		{
			name:    "unexpected additional field is rejected",
			body:    `{"email":"user@example.com","password":"` + validPassword + `","remember_me":true}`,
			wantErr: validation.ErrUnknownField,
		},
		{
			name:    "malformed JSON is rejected",
			body:    `{"email":`,
			wantErr: validation.ErrMalformedJSON,
		},
		{
			name:    "payload exceeding the size limit is rejected",
			body:    `{"email":"user@example.com","password":"` + strings.Repeat("a", 2010) + `"}`,
			wantErr: validation.ErrPayloadTooLarge,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validation.DecodeLoginRequest(strings.NewReader(tt.body))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("DecodeLoginRequest() error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got != tt.want {
				t.Fatalf("DecodeLoginRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
