package crypto

import (
	"crypto/rsa"
	"fmt"
	"os"
	"crypto/x509"
	"encoding/pem"
	"github.com/golang-jwt/jwt/v5"

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

func NewJWTService(privateKeyPath, publicKeyPath, issuer, audience string)(*JWTService, error){
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
		publicKey: publicKey,
		issuer: issuer,
		audience: audience,
	}, nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error){
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

func loadPublicKey(path string )(*rsa.PublicKey, error){
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	pub , err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	return publicKey, nil
}