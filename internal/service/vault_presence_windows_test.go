//go:build windows

package service

import (
	"context"
	"errors"
	"testing"
)

func TestWindowsPresenceSelectsHelloWhenUsable(t *testing.T) {
	restore := installWindowsPresenceFakes(t, windowsPresenceFakeConfig{
		build:       windowsHelloMinBuild,
		hwnd:        100,
		helloUsable: true,
		credUsable:  true,
	})
	defer restore()

	authorizer := &windowsPromptAuthorizer{}
	if got := authorizer.Kind(); got != windowsPresenceHello {
		t.Fatalf("expected %s, got %s", windowsPresenceHello, got)
	}
	available, _ := authorizer.Available(context.Background())
	if !available || !authorizer.UserPresence() {
		t.Fatalf("expected available user presence")
	}
}

func TestWindowsPresenceSelectsHelloOnWindows10WhenUsable(t *testing.T) {
	restore := installWindowsPresenceFakes(t, windowsPresenceFakeConfig{
		build:       windowsHelloMinBuild - 1,
		hwnd:        0,
		helloUsable: true,
		credUsable:  true,
	})
	defer restore()

	authorizer := &windowsPromptAuthorizer{}
	if got := authorizer.Kind(); got != windowsPresenceHello {
		t.Fatalf("expected %s, got %s", windowsPresenceHello, got)
	}
}

func TestWindowsPresenceFallsBackToCredUI(t *testing.T) {
	restore := installWindowsPresenceFakes(t, windowsPresenceFakeConfig{
		build:       windowsHelloMinBuild - 1,
		hwnd:        100,
		helloUsable: false,
		credUsable:  true,
	})
	defer restore()

	authorizer := &windowsPromptAuthorizer{}
	if got := authorizer.Kind(); got != windowsPresenceCredUI {
		t.Fatalf("expected %s, got %s", windowsPresenceCredUI, got)
	}
}

func TestWindowsPresenceRequireUsesCredUIAfterHelloFailure(t *testing.T) {
	var helloCalls int
	var credCalls int
	restore := installWindowsPresenceFakes(t, windowsPresenceFakeConfig{
		build:       windowsHelloMinBuild,
		hwnd:        100,
		helloUsable: true,
		credUsable:  true,
		helloPrompt: func(ctx context.Context, message string, hwnd uintptr) error {
			helloCalls++
			return errors.New("hello canceled")
		},
		credPrompt: func(ctx context.Context, message string, hwnd uintptr) error {
			credCalls++
			return nil
		},
	})
	defer restore()

	authorizer := &windowsPromptAuthorizer{}
	if err := authorizer.Require(context.Background(), "vault-id", vaultAccessRead); err != nil {
		t.Fatalf("Require failed: %v", err)
	}
	if helloCalls != 1 || credCalls != 1 {
		t.Fatalf("expected one hello and one CredUI call, got hello=%d cred=%d", helloCalls, credCalls)
	}
}

func TestWindowsPresenceUnavailable(t *testing.T) {
	restore := installWindowsPresenceFakes(t, windowsPresenceFakeConfig{
		build:       windowsHelloMinBuild,
		hwnd:        0,
		helloUsable: false,
		credUsable:  false,
	})
	defer restore()

	authorizer := &windowsPromptAuthorizer{}
	if got := authorizer.Kind(); got != windowsPresenceNone {
		t.Fatalf("expected %s, got %s", windowsPresenceNone, got)
	}
	if available, _ := authorizer.Available(context.Background()); available {
		t.Fatalf("expected unavailable presence backend")
	}
	if authorizer.UserPresence() {
		t.Fatalf("expected no user presence capability")
	}
}

type windowsPresenceFakeConfig struct {
	build       uint32
	hwnd        uintptr
	helloUsable bool
	credUsable  bool
	helloPrompt func(context.Context, string, uintptr) error
	credPrompt  func(context.Context, string, uintptr) error
}

func installWindowsPresenceFakes(t *testing.T, cfg windowsPresenceFakeConfig) func() {
	t.Helper()
	previousBuild := windowsCurrentBuild
	previousWindow := windowsConsoleWindow
	previousHelloUsable := windowsHelloUsable
	previousHelloPrompt := windowsHelloPrompt
	previousCredUsable := windowsCredUIUsable
	previousCredPrompt := windowsCredUIPrompt

	windowsCurrentBuild = func() uint32 { return cfg.build }
	windowsConsoleWindow = func() uintptr { return cfg.hwnd }
	windowsHelloUsable = func(ctx context.Context) bool { return cfg.helloUsable }
	windowsCredUIUsable = func() bool { return cfg.credUsable }
	if cfg.helloPrompt != nil {
		windowsHelloPrompt = cfg.helloPrompt
	} else {
		windowsHelloPrompt = func(ctx context.Context, message string, hwnd uintptr) error { return nil }
	}
	if cfg.credPrompt != nil {
		windowsCredUIPrompt = cfg.credPrompt
	} else {
		windowsCredUIPrompt = func(ctx context.Context, message string, hwnd uintptr) error { return nil }
	}

	return func() {
		windowsCurrentBuild = previousBuild
		windowsConsoleWindow = previousWindow
		windowsHelloUsable = previousHelloUsable
		windowsHelloPrompt = previousHelloPrompt
		windowsCredUIUsable = previousCredUsable
		windowsCredUIPrompt = previousCredPrompt
	}
}
