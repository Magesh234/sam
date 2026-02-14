package crypto

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"
	"strings"
	"github.com/xlzd/gotp"
)

func GenerateMFASecret() (string, error) {
	scr := make([]byte, 20)
	_, err := rand.Read(scr)
	if err != nil {
		return "", fmt.Errorf("failed to generate MFA secret: %w", err)
	}
	enc := base32.StdEncoding.EncodeToString(scr)
	enc = strings.TrimRight(enc, "=")
	return enc, nil
}

func ValidateMFACode(scr, cd string) bool {
	totp := gotp.NewDefaultTOTP(scr)
	return totp.Verify(cd, int(gotp.TimeNow()))
}

