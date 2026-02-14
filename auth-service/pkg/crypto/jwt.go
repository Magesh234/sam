package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	audience   string
}

type AccessTokenClaims struct {
	UserID         string   `json:"sub"`
	Username       string   `json:"username"`
	Email          string   `json:"email"`
	Roles          []string `json:"roles"`
	Permissions    []string `json:"permissions"`
	OrganizationID string   `json:"org_id,omitempty"`
	DepartmentID   string   `json:"dept_id,omitempty"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

type MFATempTokenClaims struct {
	UserID    string `json:"user_id"`
	TokenType string `json:"token_type"`
	jwt.RegisteredClaims
}

func NewJWTService(privateKeyPath, publicKeyPath, issuer, audience string) (*JWTService, error) {
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}
	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key: %w", err)
	}

	return &JWTService{
		privateKey: privateKey,
		publicKey:  publicKey,
		issuer:     issuer,
		audience:   audience,
	}, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key")
		}
	}
	return privateKey, nil

}

func loadPublicKey(path string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return publicKey, nil
}

func (s *JWTService) GenerateAccessToken(userID, username, email string,
	roles, permissions []string,
	orgID, deptID string,
	duration time.Duration) (string, error) {
	now := time.Now()
	claims := AccessTokenClaims{
		UserID:         userID,
		Username:       username,
		Email:          email,
		Roles:          roles,
		Permissions:    permissions,
		OrganizationID: orgID,
		DepartmentID:   deptID,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.issuer,
			Audience:  []string{s.audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			NotBefore: jwt.NewNumericDate(now),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign access token: %w", err)
	}
	return tokenString, nil
}

func (s *JWTService) GenerateRefreshToken(userID string, duration time.Duration) (string, error) {
	now := time.Now()
	jti := uuid.New().String()
	claims := RefreshTokenClaims{
		TokenType: "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    s.issuer,
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign refresh token: %w", err)
	}
	return tokenString, jti, nil
}

func (s *JWTService) GenerateMFATempToken(userID string, duration time.Duration) (string, error) {
	now := time.Now()

	claims := MFATempTokenClaims{
		UserID:    userID,
		TokenType: "mfa_temp",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			ExpiresAt: jwt.NewNumericDate(now.Add(duration)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    s.issuer,
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign MFA temp token: %w", err)
	}

	return tokenString, nil
}

func (s *JWTService) ValidateAccessToken(tokenString string) (*AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*AccessTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *JWTService) ValidateRefreshToken(tokenString string) (*RefreshTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &RefreshTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*RefreshTokenClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *JWTService) ValidateMFATempToken(tokenString string) (*MFATempTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &MFATempTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if claims, ok := token.Claims.(*MFATempTokenClaims); ok && token.Valid {
		if claims.TokenType != "mfa_temp" {
			return nil, fmt.Errorf("invalid token type")
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *JWTService) GetPublicKey() *rsa.PublicKey {
	return s.publicKey
}
