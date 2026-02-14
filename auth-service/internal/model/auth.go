package model

import "time"

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type LoginResponse struct {
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    int64         `json:"expires_in"`
	User         UserWithRoles `json:"user"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type RefreshTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in"`
}

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" `
}

type MFARequiredResponse struct {
	MFARequired bool   `json:"mfa_required"`
	TempToken   string `json:"temp_token,omitempty"`
}
type VerifyTokenRequest struct {
	Token string `json:"token" binding:"required"`
}
type VerifyTokenResponse struct {
	Valid       bool     `json:"valid"`
	UserID      string   `json:"user_id,omitempty"`
	Username    string   `json:"username,omitempty"`
	Roles       []string `json:"roles,omitempty"`
	permissions []string `json:"permissions,omitempty"`
	ExpiresAt   int64    `json:"expires_at,omitempty"`
}

type forgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type RegisterRequest struct {
	Username       string  `json:"username" binding:"required,min=3,max=50"`
	Email          string  `json:"email" binding:"required,email"`
	Password       string  `json:"password" binding:"required,min=8"`	
	FirstName      string  `json:"first_name"`
	LastName       string  `json:"last_name"`
	OrganizationID *string `json:"organization_id"`
}
type MFAEnableRequest struct {
	Password string `json:"password" binding:"required"`
}

type MFAEnableResponse struct {
	Secret      string   `json:"secret"`
	QRCode      string   `json:"qr_code"`
	BackupCodes []string `json:"backup_codes"`
}

type MFAVerifyRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type MFADisableRequest struct {
	Password string `json:"password" binding:"required"`
	Code     string `json:"code" binding:"required,len=6"`
}

type RefreshTokenData struct {
	ID          string
	UserID      string
	TokenJTI    string
	TokenHash   string
	DeviceInfo  string
	IPAddress   string
	ExpiresAt   time.Time
	Revoked     bool
	RevokedAt   *time.Time
	CreatedAt   time.Time
	LastUsedAt  *time.Time
}

type PasswordResetToken struct {
	ID        string
	UserID    string
	Token     string
	ExpiresAt time.Time
	Used      bool
	UsedAt    *time.Time
	CreatedAt time.Time
}


