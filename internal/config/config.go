// Package config reads server configuration from the environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const minSecretLength = 24

type Config struct {
	Secret         string
	PublicURL      string
	Addr           string
	DatabaseURL    string
	S3Endpoint     string
	S3AccessKey    string
	S3SecretKey    string
	S3Bucket       string
	S3Region       string
	Retention      time.Duration
	MaxUploadBytes int64
	PurgeInterval  time.Duration
	Version        string
	// Hack Club Auth sign-in for email-restricted files. Off when the client
	// ID and secret are unset.
	HCAClientID     string
	HCAClientSecret string
	HCAURL          string
}

func Load(getenv func(string) string) (Config, error) {
	get := func(key, fallback string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return fallback
	}
	cfg := Config{
		Secret:        getenv("MCP_SECRET"),
		Addr:          get("ADDR", "127.0.0.1:8080"),
		DatabaseURL:   get("DATABASE_URL", ""),
		S3Endpoint:    get("S3_ENDPOINT", ""),
		S3AccessKey:   get("S3_ACCESS_KEY", ""),
		S3SecretKey:   get("S3_SECRET_KEY", ""),
		S3Bucket:      get("S3_BUCKET", ""),
		S3Region:      get("S3_REGION", "us-east-1"),
		PurgeInterval: time.Hour,
		Version:       get("SOURCE_COMMIT", "dev"),

		HCAClientID:     get("HCA_CLIENT_ID", ""),
		HCAClientSecret: get("HCA_CLIENT_SECRET", ""),
		HCAURL:          strings.TrimRight(get("HCA_URL", "https://auth.hackclub.com"), "/"),
	}
	cfg.PublicURL = strings.TrimRight(get("PUBLIC_URL", "http://"+cfg.Addr), "/")

	if len(cfg.Secret) < minSecretLength {
		return Config{}, fmt.Errorf("MCP_SECRET must be at least %d characters", minSecretLength)
	}
	if err := checkPublicURL(cfg.PublicURL); err != nil {
		return Config{}, err
	}
	for key, value := range map[string]string{"DATABASE_URL": cfg.DatabaseURL, "S3_ENDPOINT": cfg.S3Endpoint,
		"S3_ACCESS_KEY": cfg.S3AccessKey, "S3_SECRET_KEY": cfg.S3SecretKey, "S3_BUCKET": cfg.S3Bucket} {
		if value == "" {
			return Config{}, fmt.Errorf("%s is required", key)
		}
	}
	if (cfg.HCAClientID == "") != (cfg.HCAClientSecret == "") {
		return Config{}, errors.New("set both HCA_CLIENT_ID and HCA_CLIENT_SECRET, or neither")
	}
	days, err := strconv.Atoi(get("RETENTION_DAYS", "30"))
	if err != nil || days < 1 {
		return Config{}, errors.New("RETENTION_DAYS must be a whole number of days, at least 1")
	}
	cfg.Retention = time.Duration(days) * 24 * time.Hour
	mb, err := strconv.ParseInt(get("MAX_UPLOAD_MB", "5120"), 10, 64)
	if err != nil || mb < 1 {
		return Config{}, errors.New("MAX_UPLOAD_MB must be a positive whole number")
	}
	cfg.MaxUploadBytes = mb << 20
	return cfg, nil
}

func checkPublicURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" {
		return fmt.Errorf("PUBLIC_URL %q is not an absolute URL", value)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("PUBLIC_URL must be an origin with no path, e.g. https://files.example.com")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if u.Scheme == "http" && (host == "localhost" || net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback()) {
		return nil
	}
	return errors.New("PUBLIC_URL must use https unless it is a loopback address")
}
