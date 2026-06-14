package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/termix"
)

func (r *runtime) newBackendCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backend",
		Short: "Manage optional external sync backends",
	}
	cmd.AddCommand(r.newBackendTermixCmd())
	return cmd
}

func (r *runtime) newBackendTermixCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "termix",
		Short: "Manage Termix sync backend registrations",
	}
	cmd.AddCommand(
		r.newBackendTermixAddCmd(),
		r.newBackendTermixListCmd(),
		r.newBackendTermixShowCmd(),
	)
	return cmd
}

func (r *runtime) newBackendTermixAddCmd() *cobra.Command {
	var (
		rawURL             string
		token              string
		profileSpec        string
		createProfile      bool
		insecureSkipVerify bool
		caFile             string
		noValidate         bool
	)
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Register a Termix instance as an optional sync backend",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := strings.TrimSpace(args[0])
			if name == "" {
				return errors.New("name is required")
			}
			normalizedURL, err := termix.NormalizeBaseURL(rawURL)
			if err != nil {
				return err
			}
			token = strings.TrimSpace(token)
			if token == "" {
				return errors.New("token is required")
			}
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()

			targetProfileID, err := resolveOrCreateBackendProfile(cmd.Context(), catalog, profileSpec, createProfile)
			if err != nil {
				return err
			}

			backend := domain.Backend{
				Name:               name,
				Type:               domain.BackendTypeTermix,
				URL:                normalizedURL,
				Token:              token,
				InsecureSkipVerify: insecureSkipVerify,
				CAFile:             strings.TrimSpace(caFile),
				TargetProfileRef:   targetProfileID,
			}
			if !noValidate {
				client, err := termix.NewClient(normalizedURL, termix.Options{
					Token:              token,
					InsecureSkipVerify: insecureSkipVerify,
					CAFile:             backend.CAFile,
				})
				if err != nil {
					return err
				}
				if err := client.Health(cmd.Context()); err != nil {
					return err
				}
				user, err := client.CurrentUser(cmd.Context())
				if err != nil {
					return err
				}
				backend.RemoteUserID = user.UserID
				backend.RemoteUser = user.Username
				connectedAt := time.Now().UTC()
				backend.LastConnectedAt = &connectedAt
				if !user.DataUnlocked {
					backend.LastSyncError = "Termix user data is locked; future secret sync will require unlocking Termix user data"
				}
			}
			if err := catalog.SaveBackend(cmd.Context(), &backend); err != nil {
				return err
			}
			return printJSON(backend)
		},
	}
	cmd.Flags().StringVar(&rawURL, "url", "", "Termix base URL, for example http://localhost:8080")
	cmd.Flags().StringVar(&token, "token", "", "Termix API token (avoid passing on shared shells)")
	cmd.Flags().StringVar(&profileSpec, "profile", "", "Local profile name or ID used as this backend's sync target")
	cmd.Flags().BoolVar(&createProfile, "create-profile", false, "Create --profile if no existing profile matches")
	cmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip TLS certificate verification for this backend")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "CA certificate bundle for this backend")
	cmd.Flags().BoolVar(&noValidate, "no-validate", false, "Save the backend without contacting Termix")
	_ = cmd.MarkFlagRequired("url")
	return cmd
}

func (r *runtime) newBackendTermixListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered Termix backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			backends, err := catalog.ListBackends(cmd.Context())
			if err != nil {
				return err
			}
			out := make([]domain.Backend, 0, len(backends))
			for _, backend := range backends {
				if backend.Type == domain.BackendTypeTermix {
					out = append(out, backend)
				}
			}
			return printJSON(out)
		},
	}
}

func (r *runtime) newBackendTermixShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "show <name-or-id>",
		Aliases: []string{"get"},
		Short:   "Show a registered Termix backend",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			id, err := catalog.ResolveDocumentID(cmd.Context(), domain.KindBackend, args[0])
			if err != nil {
				return err
			}
			backend, err := catalog.GetBackend(cmd.Context(), id)
			if err != nil {
				return err
			}
			if backend.Type != domain.BackendTypeTermix {
				return fmt.Errorf("%s is %s, not termix", args[0], backend.Type)
			}
			return printJSON(backend)
		},
	}
}

func resolveOrCreateBackendProfile(ctx context.Context, catalog *service.Catalog, profileSpec string, createProfile bool) (string, error) {
	profileSpec = strings.TrimSpace(profileSpec)
	if profileSpec == "" {
		return "", nil
	}
	id, err := catalog.ResolveDocumentID(ctx, domain.KindProfile, profileSpec)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("profile %q: %w", profileSpec, err)
	}
	if !createProfile {
		return "", fmt.Errorf("profile %q: %w", profileSpec, err)
	}
	profile := &domain.Profile{Name: profileSpec}
	if err := catalog.SaveProfile(ctx, profile); err != nil {
		return "", err
	}
	return profile.ID, nil
}
