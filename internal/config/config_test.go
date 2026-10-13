package config

import (
	"strings"
	"testing"
	"time"
)

func env(overrides map[string]string) func(string) string {
	base := map[string]string{
		"MCP_SECRET":    "0123456789abcdefghijklmnopqrstuv",
		"PUBLIC_URL":    "https://files.example.com/",
		"DATABASE_URL":  "postgres://localhost/files",
		"S3_ENDPOINT":   "http://garage.internal:3900",
		"S3_ACCESS_KEY": "GKabc",
		"S3_SECRET_KEY": "shh",
		"S3_BUCKET":     "zachlatta-file-share",
	}
	for k, v := range overrides {
		base[k] = v
	}
	return func(k string) string { return base[k] }
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://files.example.com" || cfg.Retention != 30*24*time.Hour || cfg.MaxUploadBytes != 5<<30 ||
		cfg.Addr != "127.0.0.1:8080" || cfg.S3Region != "us-east-1" || cfg.Version != "dev" || cfg.PurgeInterval != time.Hour {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestOverrides(t *testing.T) {
	cfg, err := Load(env(map[string]string{"RETENTION_DAYS": "90", "MAX_UPLOAD_MB": "100", "S3_REGION": "zrl-home", "SOURCE_COMMIT": "abc123", "ADDR": "0.0.0.0:8080"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Retention != 90*24*time.Hour || cfg.MaxUploadBytes != 100<<20 || cfg.S3Region != "zrl-home" || cfg.Version != "abc123" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]map[string]string{
		"MCP_SECRET":     {"MCP_SECRET": "short"},
		"PUBLIC_URL":     {"PUBLIC_URL": "http://files.example.com"},
		"PUBLIC_URL ":    {"PUBLIC_URL": "https://files.example.com/sub"},
		"DATABASE_URL":   {"DATABASE_URL": ""},
		"S3_BUCKET":      {"S3_BUCKET": ""},
		"RETENTION_DAYS": {"RETENTION_DAYS": "0"},
		"MAX_UPLOAD_MB":  {"MAX_UPLOAD_MB": "lots"},
	}
	for want, override := range cases {
		_, err := Load(env(override))
		if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(want)) {
			t.Errorf("%s: err = %v", want, err)
		}
	}
	if _, err := Load(env(map[string]string{"PUBLIC_URL": "http://127.0.0.1:8080"})); err != nil {
		t.Errorf("loopback http should be allowed: %v", err)
	}
}

func TestHackClubAuth(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil || cfg.HCAClientID != "" {
		t.Fatalf("default should leave Hack Club Auth off: %+v %v", cfg, err)
	}
	cfg, err = Load(env(map[string]string{"HCA_CLIENT_ID": "cid", "HCA_CLIENT_SECRET": "csecret"}))
	if err != nil || cfg.HCAClientID != "cid" || cfg.HCAClientSecret != "csecret" || cfg.HCAURL != "https://auth.hackclub.com" {
		t.Fatalf("cfg = %+v, %v", cfg, err)
	}
	for _, partial := range []map[string]string{{"HCA_CLIENT_ID": "cid"}, {"HCA_CLIENT_SECRET": "csecret"}} {
		if _, err := Load(env(partial)); err == nil || !strings.Contains(err.Error(), "HCA_CLIENT") {
			t.Errorf("%v: %v", partial, err)
		}
	}
}

func TestAdminAndClientIP(t *testing.T) {
	cfg, err := Load(env(nil))
	if err != nil || cfg.AdminToken != "" || cfg.ClientIPHeader != "" {
		t.Fatalf("defaults: %+v %v", cfg, err)
	}
	cfg, err = Load(env(map[string]string{"ADMIN_TOKEN": "admin-token-0123456789abcdefgh", "CLIENT_IP_HEADER": "CF-Connecting-IP"}))
	if err != nil || cfg.AdminToken != "admin-token-0123456789abcdefgh" || cfg.ClientIPHeader != "CF-Connecting-IP" {
		t.Fatalf("cfg = %+v, %v", cfg, err)
	}
	if _, err := Load(env(map[string]string{"ADMIN_TOKEN": "short"})); err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("short admin token: %v", err)
	}
	if _, err := Load(env(map[string]string{"ADMIN_TOKEN": "0123456789abcdefghijklmnopqrstuv"})); err == nil || !strings.Contains(err.Error(), "ADMIN_TOKEN") {
		t.Fatalf("admin token equal to MCP_SECRET: %v", err)
	}
}
