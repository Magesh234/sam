package model

import (
	"database/sql"
	"time"
)

type User struct {
	ID                   string         `json:"id"`
	Username             string         `json:"username"`
	Email                string         `json:"email"`
	PasswordHash         string         `json:"-"`
	FirstName            sql.NullString `json:"first_name,omitempty"`
	LastName             sql.NullString `json:"last_name,omitempty"`
	Phone                sql.NullString `json:"phone,omitempty"`
	Status               string         `json:"status"`
	EmailVerified        bool           `json:"email_verified"`
	MustChangePassword   bool           `json:"must_change_password"`
	FailedLoginAttempts  int            `json:"-"`
	LastFailedLogin      sql.NullTime   `json:"-"`
	LockedUntil          sql.NullTime   `json:"-"`
	PasswordChangedAt    sql.NullTime   `json:"-"`
	LastLoginAt          sql.NullTime   `json:"last_login_at,omitempty"`
	LastLoginIP          sql.NullString `json:"-"`
	MFAEnabled           bool           `json:"mfa_enabled"`
	MFASecret            sql.NullString `json:"-"`
	MFABackupCodes       sql.NullString `json:"-"`
	OrganizationID       sql.NullString `json:"organization_id,omitempty"`
	DepartmentID         sql.NullString `json:"department_id,omitempty"`
	CreatedAt            time.Time      `json:"created_at"`
	UpdatedAt            time.Time      `json:"updated_at"`
	DeletedAt            sql.NullTime   `json:"-"`
}

type UserWithRoles struct {
	User
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type CreateUserRequest struct {
	Username       string  `json:"username" binding:"required,min=3,max=50"`
	Email          string  `json:"email" binding:"required,email"`
	Password       string  `json:"password" binding:"required,min=8"`
	FirstName      string  `json:"first_name"`
	LastName       string  `json:"last_name"`
	Phone          string  `json:"phone"`
	OrganizationID *string `json:"organization_id"`
	DepartmentID   *string `json:"department_id"`
	RoleIDs        []string `json:"role_ids"`
}

type UpdateUserRequest struct {
	Email          *string  `json:"email" binding:"omitempty,email"`
	FirstName      *string  `json:"first_name"`
	LastName       *string  `json:"last_name"`
	Phone          *string  `json:"phone"`
	Status         *string  `json:"status" binding:"omitempty,oneof=active inactive locked"`
	OrganizationID *string  `json:"organization_id"`
	DepartmentID   *string  `json:"department_id"`
}

type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required,min=8"`
}

type UserListFilter struct {
	Status         *string
	OrganizationID *string
	DepartmentID   *string
	Search         *string
	Page           int
	PageSize       int
	SortBy         string
	SortOrder      string
}