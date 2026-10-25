package auth

import (
	"errors"
	"fmt"

	"github.com/alexedwards/argon2id"
)

var (
	ErrPasswordMismatch = errors.New("password does not match")
	ErrInvalidHash      = errors.New("invalid password hash format")
	ErrWeakPassword     = errors.New("password does not meet requirements")
)

// OWASP recommended Argon2id params (as of 2024)
var defaultParams = &argon2id.Params{
	Memory:      64 * 1024, // 64 MB
	Iterations:  3,
	Parallelism: 2,
	SaltLength:  16,
	KeyLength:   32,
}

// HashPassword returns an argon2id encoded string like:
// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
func HashPassword(password string) (string, error) {
	if err := ValidatePasswordStrength(password); err != nil {
		return "", err
	}
	hash, err := argon2id.CreateHash(password, defaultParams)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return hash, nil
}

// VerifyPassword checks a plaintext password against an argon2id hash.
func VerifyPassword(password, encodedHash string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(password, encodedHash)
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrInvalidHash, err)
	}
	if !match {
		return false, ErrPasswordMismatch
	}
	return true, nil
}

// ValidatePasswordStrength enforces: >=8 chars, upper + lower + digit.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("%w: minimum 8 characters", ErrWeakPassword)
	}
	if len(password) > 128 {
		return fmt.Errorf("%w: maximum 128 characters", ErrWeakPassword)
	}

	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return fmt.Errorf("%w: must contain uppercase, lowercase, and digit", ErrWeakPassword)
	}
	return nil
}

// DummyHash is used to normalize timing when the user does not exist,
// so attackers cannot tell "email not found" from "wrong password"
// by measuring response time.
var DummyHash string

func init() {
	// Hash is generated once at startup (~50-100ms), acceptable.
	h, err := argon2id.CreateHash("dummy-password-for-timing-equalization", defaultParams)
	if err == nil {
		DummyHash = h
	}
}
