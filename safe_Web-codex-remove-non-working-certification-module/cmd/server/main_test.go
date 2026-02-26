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
