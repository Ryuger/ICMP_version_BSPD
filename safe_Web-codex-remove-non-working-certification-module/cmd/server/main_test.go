package main

import "testing"

func TestBuildPublicTLSConfig(t *testing.T) {
	cfg, err := buildPublicTLSConfig()
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil tls config")
	}
}

func TestPasswordComplexity(t *testing.T) {
	if !checkPasswordComplexity("StrongPass123!") {
		t.Fatal("expected strong password to pass")
	}
	if checkPasswordComplexity("weak") {
		t.Fatal("expected weak password to fail")
	}
}

func TestParseServerRole(t *testing.T) {
	pub, adm, err := parseServerRole("public")
	if err != nil || !pub || adm {
		t.Fatalf("public role parse failed: pub=%v admin=%v err=%v", pub, adm, err)
	}

	pub, adm, err = parseServerRole("admin")
	if err != nil || pub || !adm {
		t.Fatalf("admin role parse failed: pub=%v admin=%v err=%v", pub, adm, err)
	}

	pub, adm, err = parseServerRole("all")
	if err != nil || !pub || !adm {
		t.Fatalf("all role parse failed: pub=%v admin=%v err=%v", pub, adm, err)
	}

	if _, _, err = parseServerRole("bad"); err == nil {
		t.Fatal("expected parse error for invalid role")
	}
}
