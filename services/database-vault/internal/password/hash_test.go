package password

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// Requirement: DV-F-07
func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() unexpected error = %v", err)
	}
	if len(salt) != saltSize {
		t.Fatalf("GenerateSalt() length = %d, want %d", len(salt), saltSize)
	}

	other, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt() second call unexpected error = %v", err)
	}
	if bytes.Equal(salt, other) {
		t.Fatalf("GenerateSalt() produced identical salts on two calls: %x", salt)
	}
}

// Requirement: DV-F-07
//
// Known-answer vector: independently reimplements the exact
// argon2.IDKey(password||pepper, salt, ...) computation HashPassword's doc
// comment specifies, then checks HashPassword's PHC-encoded output decodes
// to that same digest — not merely that HashPassword doesn't error.
func TestHashPassword_KnownAnswer(t *testing.T) {
	password := []byte("Str0ng!Pass")
	pepper := []byte("some-pepper")
	salt := []byte("0123456789abcdef") // 16 bytes, matches saltSize

	got, err := HashPassword(password, salt, pepper)
	if err != nil {
		t.Fatalf("HashPassword() unexpected error = %v", err)
	}

	wantHash := argon2.IDKey(
		append(append([]byte{}, password...), pepper...),
		salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen,
	)

	_, gotHash, gotTime, gotMemory, gotThreads, err := decodeHash(got)
	if err != nil {
		t.Fatalf("decodeHash(%q) unexpected error = %v", got, err)
	}
	if !bytes.Equal(gotHash, wantHash) {
		t.Fatalf("HashPassword() digest = %x, want %x", gotHash, wantHash)
	}
	if gotTime != argonTime || gotMemory != argonMemoryKiB || gotThreads != argonThreads {
		t.Fatalf("HashPassword() params = (time=%d, memory=%d, threads=%d), want (time=%d, memory=%d, threads=%d)",
			gotTime, gotMemory, gotThreads, argonTime, argonMemoryKiB, argonThreads)
	}
}

// Requirement: DV-F-07
func TestHashPassword_EncodingFormat(t *testing.T) {
	salt := []byte("0123456789abcdef")
	got, err := HashPassword([]byte("Str0ng!Pass"), salt, []byte("pepper"))
	if err != nil {
		t.Fatalf("HashPassword() unexpected error = %v", err)
	}

	wantPrefix := "$argon2id$v=19$m=47104,t=2,p=1$"
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("HashPassword() = %q, want prefix %q", got, wantPrefix)
	}
}

// Requirement: DV-F-07
func TestHashPassword_InvalidSaltLength(t *testing.T) {
	tests := []struct {
		name string
		salt []byte
	}{
		{name: "empty salt", salt: []byte{}},
		{name: "too short", salt: []byte("short")},
		{name: "too long", salt: bytes.Repeat([]byte("a"), saltSize+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HashPassword([]byte("Str0ng!Pass"), tt.salt, []byte("pepper"))
			if !errors.Is(err, ErrPasswordHashInvalidSalt) {
				t.Fatalf("HashPassword() error = %v, want ErrPasswordHashInvalidSalt", err)
			}
		})
	}
}

// Requirement: DV-F-07
func TestHashPassword_Deterministic(t *testing.T) {
	password := []byte("Str0ng!Pass")
	pepper := []byte("pepper")
	salt := []byte("0123456789abcdef")

	first, err := HashPassword(password, salt, pepper)
	if err != nil {
		t.Fatalf("HashPassword() first call unexpected error = %v", err)
	}
	second, err := HashPassword(password, salt, pepper)
	if err != nil {
		t.Fatalf("HashPassword() second call unexpected error = %v", err)
	}

	if first != second {
		t.Fatalf("HashPassword() not deterministic: first = %q, second = %q", first, second)
	}
}

// Requirement: DV-F-07
func TestHashPassword_DifferentInputsProduceDifferentHashes(t *testing.T) {
	basePassword := []byte("Str0ng!Pass")
	basePepper := []byte("pepper")
	baseSalt := []byte("0123456789abcdef")

	base, err := HashPassword(basePassword, baseSalt, basePepper)
	if err != nil {
		t.Fatalf("HashPassword() base case unexpected error = %v", err)
	}

	tests := []struct {
		name     string
		password []byte
		salt     []byte
		pepper   []byte
	}{
		{
			name:     "different password",
			password: []byte("Different1!"),
			salt:     baseSalt,
			pepper:   basePepper,
		},
		{
			name:     "different salt",
			password: basePassword,
			salt:     []byte("fedcba9876543210"),
			pepper:   basePepper,
		},
		{
			name:     "different pepper",
			password: basePassword,
			salt:     baseSalt,
			pepper:   []byte("different-pepper"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := HashPassword(tt.password, tt.salt, tt.pepper)
			if err != nil {
				t.Fatalf("HashPassword() unexpected error = %v", err)
			}
			if got == base {
				t.Fatalf("HashPassword() produced identical output to base case for %s", tt.name)
			}
		})
	}
}

// Requirement: DV-F-07
func TestVerifyPassword(t *testing.T) {
	password := []byte("Str0ng!Pass")
	pepper := []byte("pepper")
	salt := []byte("0123456789abcdef")

	encoded, err := HashPassword(password, salt, pepper)
	if err != nil {
		t.Fatalf("HashPassword() unexpected error = %v", err)
	}

	tests := []struct {
		name     string
		password []byte
		pepper   []byte
		encoded  string
		want     bool
		wantErr  bool
	}{
		{
			name:     "matching password and pepper verifies",
			password: password,
			pepper:   pepper,
			encoded:  encoded,
			want:     true,
		},
		{
			name:     "wrong password does not verify",
			password: []byte("Wr0ng!Pass"),
			pepper:   pepper,
			encoded:  encoded,
			want:     false,
		},
		{
			name:     "wrong pepper does not verify",
			password: password,
			pepper:   []byte("wrong-pepper"),
			encoded:  encoded,
			want:     false,
		},
		{
			name:     "malformed encoded hash returns error",
			password: password,
			pepper:   pepper,
			encoded:  "not-a-valid-phc-string",
			wantErr:  true,
		},
		{
			name:     "unsupported algorithm returns error",
			password: password,
			pepper:   pepper,
			encoded:  "$argon2i$v=19$m=47104,t=2,p=1$c2FsdA$aGFzaA",
			wantErr:  true,
		},
		{
			name:     "negative cost parameter returns error",
			password: password,
			pepper:   pepper,
			encoded:  "$argon2id$v=19$m=47104,t=-2,p=1$c2FsdA$aGFzaA",
			wantErr:  true,
		},
		{
			name:     "out-of-range threads parameter returns error",
			password: password,
			pepper:   pepper,
			encoded:  "$argon2id$v=19$m=47104,t=2,p=9999$c2FsdA$aGFzaA",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyPassword(tt.password, tt.pepper, tt.encoded)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("VerifyPassword() error = nil, want error")
				}
				return
			}

			if err != nil {
				t.Fatalf("VerifyPassword() unexpected error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("VerifyPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}
