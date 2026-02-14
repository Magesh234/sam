package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"regexp"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

type PasswordHasher struct {
	cost int
}

func NewPasswordHasher(cost int) *PasswordHasher {
	return &PasswordHasher{cost: cost}
}

func (h *PasswordHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(bytes), nil
}

func (h *PasswordHasher) Verify(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (h *PasswordHasher) NeedsRehash(hash string) bool {
	cost, err := bcrypt.Cost([]byte(hash))
	if err != nil {
		return true
	}
	return cost != h.cost
}

type PasswordValidator struct {
	minLength      int
	requireUpper   bool
	requireLower   bool
	requireNumber  bool
	requireSpecial bool
}

func NewPasswordValidator(minLength int, requireUpper, requireLower, requireNumber, requireSpecial bool) *PasswordValidator {
	return &PasswordValidator{
		minLength:      minLength,
		requireUpper:   requireUpper,
		requireLower:   requireLower,
		requireNumber:  requireNumber,
		requireSpecial: requireSpecial,
	}
}

func (v *PasswordValidator) Validate(password string) error {

	if len(password) < v.minLength {
		return fmt.Errorf("password must be at least %d characters long", v.minLength)
	}
	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}
	validations := []struct {
		condition bool
		message   string
	}{
		{v.requireUpper && !hasUpper, "password must contain at least one uppercase letter"},
		{v.requireLower && !hasLower, "password must contain at least one lowercase letter"},
		{v.requireNumber && !hasNumber, "password must contain at least one number"},
		{v.requireSpecial && !hasSpecial, "password must contain at least one special character"},
	}

	for _, rule := range validations {
		if rule.condition {
			return fmt.Errorf(rule.message)
		}
	}
	weakPasswords := []string{
		"password", "123456", "123456789", "qwerty", "abc123",
		"password1", "111111", "12345678", "iloveyou", "admin",
	}
	for _, weak := range weakPasswords {
		if matched, _ := regexp.MatchString("(?i)"+weak, password); matched {
			return fmt.Errorf("password is too common or weak")
		}
	}

	return nil
}

func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random string: %w", err)
	}
	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes), nil
}
