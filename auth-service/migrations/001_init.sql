-- ==========================================
-- COMPLETE IDEMPOTENT MIGRATION
-- V001: Initial Schema and Seed Data
-- ==========================================
-- This migration is idempotent and safe to run multiple times

-- ==========================================
-- DROP EXISTING OBJECTS (in reverse dependency order)
-- ==========================================
DROP TRIGGER IF EXISTS update_depts_updated_at ON departments;
DROP TRIGGER IF EXISTS update_orgs_updated_at ON organizations;
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP FUNCTION IF EXISTS update_updated_at_column();
DROP TABLE IF EXISTS departments CASCADE;
DROP TABLE IF EXISTS organizations CASCADE;
DROP TABLE IF EXISTS audit_logs CASCADE;
DROP TABLE IF EXISTS refresh_tokens CASCADE;
DROP TABLE IF EXISTS password_reset_tokens CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS role_permissions CASCADE;
DROP TABLE IF EXISTS permissions CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- ==========================================
-- CREATE TABLES
-- ==========================================

-- ORGANIZATIONS TABLE (Multi-tenancy)
CREATE TABLE organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'suspended')),
    settings JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_orgs_slug ON organizations(slug);
CREATE INDEX idx_orgs_status ON organizations(status);

-- DEPARTMENTS TABLE
CREATE TABLE departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL,
    parent_department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    manager_id UUID,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dept_org ON departments(organization_id);
CREATE INDEX idx_dept_parent ON departments(parent_department_id);
CREATE INDEX idx_dept_manager ON departments(manager_id);

-- USERS TABLE
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    phone VARCHAR(20),
    
    -- Status
    status VARCHAR(20) DEFAULT 'active' CHECK (status IN ('active', 'inactive', 'locked', 'pending')),
    email_verified BOOLEAN DEFAULT FALSE,
    must_change_password BOOLEAN DEFAULT FALSE,
    
    -- Security
    failed_login_attempts INT DEFAULT 0,
    last_failed_login TIMESTAMP,
    locked_until TIMESTAMP,
    password_changed_at TIMESTAMP,
    last_login_at TIMESTAMP,
    last_login_ip VARCHAR(45),
    
    -- MFA
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    mfa_backup_codes TEXT,
    
    -- Organization
    organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
    department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users(status) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_org ON users(organization_id) WHERE deleted_at IS NULL;

-- Add foreign key for department manager after users table exists
ALTER TABLE departments 
    ADD CONSTRAINT fk_dept_manager 
    FOREIGN KEY (manager_id) 
    REFERENCES users(id) 
    ON DELETE SET NULL;

-- ROLES TABLE
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    description TEXT,
    parent_role_id UUID REFERENCES roles(id) ON DELETE SET NULL,
    is_system BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX idx_roles_name ON roles(name) WHERE deleted_at IS NULL;
CREATE INDEX idx_roles_parent ON roles(parent_role_id) WHERE deleted_at IS NULL;

-- PERMISSIONS TABLE
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) UNIQUE NOT NULL,
    resource VARCHAR(50) NOT NULL,
    action VARCHAR(50) NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_permissions_resource ON permissions(resource);
CREATE INDEX idx_permissions_name ON permissions(name);

-- ROLE_PERMISSIONS (Many-to-Many)
CREATE TABLE role_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID REFERENCES permissions(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(role_id, permission_id)
);

CREATE INDEX idx_role_perms_role ON role_permissions(role_id);
CREATE INDEX idx_role_perms_perm ON role_permissions(permission_id);

-- USER_ROLES (Many-to-Many)
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMP,
    UNIQUE(user_id, role_id)
);

CREATE INDEX idx_user_roles_user ON user_roles(user_id);
CREATE INDEX idx_user_roles_role ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires ON user_roles(expires_at) WHERE expires_at IS NOT NULL;

-- PASSWORD_RESET_TOKENS TABLE
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_pwd_reset_token ON password_reset_tokens(token);
CREATE INDEX idx_pwd_reset_user ON password_reset_tokens(user_id);
CREATE INDEX idx_pwd_reset_expires ON password_reset_tokens(expires_at);

-- REFRESH_TOKENS TABLE
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_jti VARCHAR(255) UNIQUE NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    device_info TEXT,
    ip_address VARCHAR(45),
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_jti ON refresh_tokens(token_jti);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_expires ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_revoked ON refresh_tokens(revoked) WHERE revoked = FALSE;

-- AUDIT_LOGS TABLE
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50),
    resource_id UUID,
    details JSONB,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_user ON audit_logs(user_id);
CREATE INDEX idx_audit_action ON audit_logs(action);
CREATE INDEX idx_audit_created ON audit_logs(created_at);
CREATE INDEX idx_audit_resource ON audit_logs(resource_type, resource_id);

-- ==========================================
-- CREATE TRIGGERS
-- ==========================================
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON users
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_roles_updated_at 
    BEFORE UPDATE ON roles
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_orgs_updated_at 
    BEFORE UPDATE ON organizations
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_depts_updated_at 
    BEFORE UPDATE ON departments
    FOR EACH ROW 
    EXECUTE FUNCTION update_updated_at_column();

-- ==========================================
-- SEED DATA: DEFAULT ROLES
-- ==========================================
INSERT INTO roles (id, name, display_name, description, is_system) VALUES
    ('00000000-0000-0000-0000-000000000001', 'super_admin', 'Super Administrator', 'Full system access', true),
    ('00000000-0000-0000-0000-000000000002', 'admin', 'Administrator', 'Administrative access', true),
    ('00000000-0000-0000-0000-000000000003', 'finance_manager', 'Finance Manager', 'Manage financial operations', true),
    ('00000000-0000-0000-0000-000000000004', 'sales_manager', 'Sales Manager', 'Manage sales operations', true),
    ('00000000-0000-0000-0000-000000000005', 'hr_manager', 'HR Manager', 'Manage HR operations', true),
    ('00000000-0000-0000-0000-000000000006', 'manager', 'Manager', 'Team management', true),
    ('00000000-0000-0000-0000-000000000007', 'user', 'User', 'Standard user access', true),
    ('00000000-0000-0000-0000-000000000008', 'read_only', 'Read Only', 'Read-only access', true);

-- ==========================================
-- SEED DATA: DEFAULT PERMISSIONS
-- ==========================================
INSERT INTO permissions (name, resource, action, description) VALUES
    -- User management
    ('users:create', 'users', 'create', 'Create new users'),
    ('users:read', 'users', 'read', 'View users'),
    ('users:update', 'users', 'update', 'Update users'),
    ('users:delete', 'users', 'delete', 'Delete users'),
    
    -- Role management
    ('roles:create', 'roles', 'create', 'Create roles'),
    ('roles:read', 'roles', 'read', 'View roles'),
    ('roles:update', 'roles', 'update', 'Update roles'),
    ('roles:delete', 'roles', 'delete', 'Delete roles'),
    
    -- Permission management
    ('permissions:read', 'permissions', 'read', 'View permissions'),
    ('permissions:assign', 'permissions', 'assign', 'Assign permissions'),
    
    -- Finance
    ('finance:read', 'finance', 'read', 'View financial data'),
    ('finance:write', 'finance', 'write', 'Create/update financial records'),
    ('finance:delete', 'finance', 'delete', 'Delete financial records'),
    ('finance:approve', 'finance', 'approve', 'Approve financial transactions'),
    
    -- Sales
    ('sales:read', 'sales', 'read', 'View sales data'),
    ('sales:write', 'sales', 'write', 'Create/update sales records'),
    ('sales:delete', 'sales', 'delete', 'Delete sales records'),
    
    -- Orders
    ('orders:create', 'orders', 'create', 'Create sales orders'),
    ('orders:read', 'orders', 'read', 'View sales orders'),
    ('orders:update', 'orders', 'update', 'Update sales orders'),
    ('orders:delete', 'orders', 'delete', 'Delete sales orders'),
    ('orders:approve', 'orders', 'approve', 'Approve sales orders'),
    
    -- Customers
    ('customers:create', 'customers', 'create', 'Create customers'),
    ('customers:read', 'customers', 'read', 'View customers'),
    ('customers:update', 'customers', 'update', 'Update customers'),
    ('customers:delete', 'customers', 'delete', 'Delete customers'),
    
    -- HR
    ('hr:read', 'hr', 'read', 'View HR data'),
    ('hr:write', 'hr', 'write', 'Create/update HR records'),
    ('hr:delete', 'hr', 'delete', 'Delete HR records'),
    
    -- Inventory
    ('inventory:read', 'inventory', 'read', 'View inventory data'),
    ('inventory:write', 'inventory', 'write', 'Manage inventory'),
    
    -- Reports
    ('reports:read', 'reports', 'read', 'View reports'),
    ('reports:export', 'reports', 'export', 'Export reports'),
    ('reports:create', 'reports', 'create', 'Create custom reports'),
    
    -- System
    ('system:admin', 'system', 'admin', 'System administration'),
    ('system:audit', 'system', 'audit', 'View audit logs');

-- ==========================================
-- SEED DATA: ROLE PERMISSIONS ASSIGNMENTS
-- ==========================================

-- Super Admin: All permissions
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000001', id FROM permissions;

-- Admin: All except system:admin and destructive operations
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000002', id FROM permissions
WHERE name NOT IN ('system:admin', 'users:delete', 'roles:delete');

-- Finance Manager: Finance, reports, and read-only customer/order access
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000003', id FROM permissions
WHERE resource IN ('finance', 'reports') OR name IN ('customers:read', 'orders:read');

-- Sales Manager: Sales, orders, customers, reports, and inventory read
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000004', id FROM permissions
WHERE resource IN ('sales', 'orders', 'customers') OR name IN ('reports:read', 'reports:export', 'inventory:read');

-- HR Manager: HR, user read, and reports
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000005', id FROM permissions
WHERE resource IN ('hr') OR name IN ('users:read', 'reports:read', 'reports:export');

-- Manager: All read permissions plus order/customer management
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000006', id FROM permissions
WHERE action = 'read' OR resource IN ('orders', 'customers');

-- User: Read access to non-sensitive resources
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000007', id FROM permissions
WHERE action = 'read' AND resource NOT IN ('users', 'roles', 'permissions', 'system');

-- Read Only: Limited read access (no HR, user, role, permission, or system access)
INSERT INTO role_permissions (role_id, permission_id)
SELECT '00000000-0000-0000-0000-000000000008', id FROM permissions
WHERE action = 'read' AND resource NOT IN ('users', 'roles', 'permissions', 'system', 'hr');

-- ==========================================
-- SEED DATA: DEFAULT ORGANIZATION
-- ==========================================
INSERT INTO organizations (id, name, slug, status, settings) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Default Organization', 'default', 'active', '{}');

-- ==========================================
-- SEED DATA: DEFAULT SUPER ADMIN USER
-- Password: Admin@123 (bcrypt hash)
-- ==========================================
INSERT INTO users (
    id,
    username,
    email,
    password_hash,
    first_name,
    last_name,
    status,
    email_verified,
    organization_id
) VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'admin@erp.local',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzpLHJ5jqW',
    'System',
    'Administrator',
    'active',
    true,
    '00000000-0000-0000-0000-000000000001'
);

-- ==========================================
-- SEED DATA: ASSIGN SUPER ADMIN ROLE
-- ==========================================
INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
    ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001');

-- ==========================================
-- MIGRATION COMPLETE
-- ==========================================