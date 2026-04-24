//go:build !windows

package service

import (
	"context"
	"errors"

	"github.com/nermius/nermius/internal/config"
)

type unavailableUnlockMaterialStore struct{}

type unavailablePresenceAuthorizer struct{}

func defaultUnlockMaterialStore(paths config.Paths) UnlockMaterialStore {
	return &unavailableUnlockMaterialStore{}
}

func defaultPresenceAuthorizer(paths config.Paths) PresenceAuthorizer {
	return &unavailablePresenceAuthorizer{}
}

func (s *unavailableUnlockMaterialStore) Kind() string { return "unavailable" }

func (s *unavailableUnlockMaterialStore) Available(ctx context.Context) (bool, string) {
	return false, "no platform unlock-material backend configured"
}

func (s *unavailableUnlockMaterialStore) IsEnrolled(ctx context.Context, vaultID string) (bool, error) {
	return false, nil
}

func (s *unavailableUnlockMaterialStore) Store(ctx context.Context, vaultID string, vaultKey []byte) error {
	return errors.New("system keychain enrollment is unavailable on this platform")
}

func (s *unavailableUnlockMaterialStore) Load(ctx context.Context, vaultID string, intent vaultAccessIntent) ([]byte, error) {
	return nil, errors.New("system keychain enrollment is unavailable on this platform")
}

func (s *unavailableUnlockMaterialStore) Delete(ctx context.Context, vaultID string) error {
	return nil
}

func (a *unavailablePresenceAuthorizer) Kind() string { return "unavailable" }

func (a *unavailablePresenceAuthorizer) Available(ctx context.Context) (bool, string) {
	return false, "no platform user-presence backend configured"
}

func (a *unavailablePresenceAuthorizer) UserPresence() bool { return false }

func (a *unavailablePresenceAuthorizer) Require(ctx context.Context, vaultID string, intent vaultAccessIntent) error {
	return nil
}
