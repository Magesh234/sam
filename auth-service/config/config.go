package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	Security SecurityConfig
}

type ServerConfig struct {
	Host         string
	Port         int
	Environment  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type DatabaseConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	DBName          string
	SSLMode         string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

type RedisConfig struct {
	Host     string
	Port     int
	Password string
	DB       int
}

type JWTConfig struct {
	PrivateKeyPath      string
	PublicKeyPath       string
	AccessTokenExpiry   time.Duration
	RefreshTokenExpiry  time.Duration
	Issuer              string
	Audience            string
}

type SecurityConfig struct {
	BcryptCost           int
	MaxLoginAttempts     int
	LockoutDuration      time.Duration
	PasswordMinLength    int
	PasswordRequireUpper bool
	PasswordRequireLower bool
	PasswordRequireNumber bool
	PasswordRequireSpecial bool
	SessionTimeout       time.Duration
	MaxConcurrentSessions int
}

func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Host:         getEnv("SERVER_HOST", "0.0.0.0"),
			Port:         getEnvAsInt("SERVER_PORT", 8080),
			Environment:  getEnv("ENVIRONMENT", "production"),
			ReadTimeout:  getEnvAsDuration("SERVER_READ_TIMEOUT", 10*time.Second),
			WriteTimeout: getEnvAsDuration("SERVER_WRITE_TIMEOUT", 10*time.Second),
			IdleTimeout:  getEnvAsDuration("SERVER_IDLE_TIMEOUT", 60*time.Second),
		},
		Database: DatabaseConfig{
			Host:            getEnv("DB_HOST", "localhost"),
			Port:            getEnvAsInt("DB_PORT", 5432),
			User:            getEnv("DB_USER", "postgres"),
			Password:        getEnv("DB_PASSWORD", ""),
			DBName:          getEnv("DB_NAME", "erp_auth_db"),
			SSLMode:         getEnv("DB_SSL_MODE", "disable"),
			MaxOpenConns:    getEnvAsInt("DB_MAX_OPEN_CONNS", 25),
			MaxIdleConns:    getEnvAsInt("DB_MAX_IDLE_CONNS", 5),
			ConnMaxLifetime: getEnvAsDuration("DB_CONN_MAX_LIFETIME", 5*time.Minute),
		},
		Redis: RedisConfig{
			Host:     getEnv("REDIS_HOST", "localhost"),
			Port:     getEnvAsInt("REDIS_PORT", 6379),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvAsInt("REDIS_DB", 0),
		},
		JWT: JWTConfig{
			PrivateKeyPath:     getEnv("JWT_PRIVATE_KEY_PATH", "./keys/private_key.pem"),
			PublicKeyPath:      getEnv("JWT_PUBLIC_KEY_PATH", "./keys/public_key.pem"),
			AccessTokenExpiry:  getEnvAsDuration("JWT_ACCESS_TOKEN_EXPIRY", 15*time.Minute),
			RefreshTokenExpiry: getEnvAsDuration("JWT_REFRESH_TOKEN_EXPIRY", 30*24*time.Hour),
			Issuer:             getEnv("JWT_ISSUER", "erp-auth-service"),
			Audience:           getEnv("JWT_AUDIENCE", "erp-api"),
		},
		Security: SecurityConfig{
			BcryptCost:            getEnvAsInt("BCRYPT_COST", 12),
			MaxLoginAttempts:      getEnvAsInt("MAX_LOGIN_ATTEMPTS", 5),
			LockoutDuration:       getEnvAsDuration("LOCKOUT_DURATION", 15*time.Minute),
			PasswordMinLength:     getEnvAsInt("PASSWORD_MIN_LENGTH", 8),
			PasswordRequireUpper:  getEnvAsBool("PASSWORD_REQUIRE_UPPER", true),
			PasswordRequireLower:  getEnvAsBool("PASSWORD_REQUIRE_LOWER", true),
			PasswordRequireNumber: getEnvAsBool("PASSWORD_REQUIRE_NUMBER", true),
			PasswordRequireSpecial: getEnvAsBool("PASSWORD_REQUIRE_SPECIAL", true),
			SessionTimeout:        getEnvAsDuration("SESSION_TIMEOUT", 30*time.Minute),
			MaxConcurrentSessions: getEnvAsInt("MAX_CONCURRENT_SESSIONS", 3),
		},
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return cfg, nil
}

func (c *Config) validate() error {
	if c.Database.Password == "" {
		return fmt.Errorf("database password is required")
	}
	if c.JWT.PrivateKeyPath == "" || c.JWT.PublicKeyPath == "" {
		return fmt.Errorf("JWT key paths are required")
	}
	if c.Security.BcryptCost < 10 || c.Security.BcryptCost > 14 {
		return fmt.Errorf("bcrypt cost must be between 10 and 14")
	}
	return nil
}

func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode,
	)
}

func (c *RedisConfig) Address() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

func getEnvAsDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}