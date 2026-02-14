package model

import (
	"database/sql"
	"time"
)

type Role struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	DisplayName  sql.NullString `json:"display_name"`
	Description  sql.NullString `json:"description,omitempty"`
	ParentRoleID sql.NullString `json:"parent_role_id,omitempty"`
	IsSystem     bool           `json:"is_system"`
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	DeletedAt    sql.NullTime   `json:"-"`
}

type RoleWithPermissions struct {
	Role
	Permissions []string `json:"permissions"`
}

type CreateRoleRequest struct {
	Name          string   `json:"name" binding:"required,min=3,max=50"`
	DisplayName   string   `json:"display_name"`
	Description   string   `json:"description"`
	ParentRoleID  *string  `json:"parent_role_id"`
	PermissionIDs []string `json:"permission_ids"`
}

type UpdateRoleRequest struct {
	DisplayName   *string  `json:"display_name"`
	Description   *string  `json:"description"`
	ParentRoleID  *string  `json:"parent_role_id"`
}

type Permission struct {
	ID 		string         `json:"id"`
	Name 	string         `json:"name"`
	Resource string         `json:"resource"`
	Action 	string         `json:"action"`
	Description sql.NullString `json:"description,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type CreatePermisionRequest struct {
	Name        string `json:"name" binding:"required,min=3,max=50"`
	Resource    string `json:"resource" binding:"required"`
	Action      string `json:"action" binding:"required"`
	Description string `json:"description"`
}
type AssignPermissionsRequest struct {
	PermissionIDs []string `json:"permission_ids" binding:"required"`
}

type AssignRolesRequest struct {
	RoleIDs []string `json:"role_ids" binding:"required"`
}

type UserRole struct {
	ID         string
	UserID     string
	RoleID     string
	AssignedAt time.Time
	AssignedBy sql.NullString
	ExpiresAt  sql.NullTime
}

type RolePermission struct {
	ID           string
	RoleID       string
	PermissionID string
	CreatedAt    time.Time
}

type Organization struct {
	ID        string
	Name      string
	Slug      string
	Status    string
	Settings  sql.NullString
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Department struct {
	ID                 string
	OrganizationID     string
	Name               string
	ParentDepartmentID sql.NullString
	ManagerID          sql.NullString
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

type AuditLog struct {
	ID           string
	UserID       sql.NullString
	Action       string
	ResourceType sql.NullString
	ResourceID   sql.NullString
	Details      sql.NullString
	IPAddress    sql.NullString
	UserAgent    sql.NullString
	CreatedAt    time.Time
}



