package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/nermius/nermius/internal/service"
)

func (r *runtime) newKnownHostsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "known-host",
		Aliases: []string{"known-hosts"},
		Short:   "Inspect and manage saved SSH host keys",
	}
	cmd.AddCommand(
		r.newKnownHostsListCmd(),
		r.newKnownHostsDeleteCmd(),
	)
	return cmd
}

func (r *runtime) newKnownHostsListCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List saved SSH host keys from vault and/or file backends",
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, paths, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			items, err := service.ListKnownHostsEntries(cmd.Context(), catalog, paths.KnownHostsPath, source)
			if err != nil {
				return err
			}
			return printJSON(items)
		},
	}
	cmd.Flags().StringVar(&source, "source", "all", "Known host source: all, vault, file")
	return cmd
}

func (r *runtime) newKnownHostsDeleteCmd() *cobra.Command {
	var source string
	cmd := &cobra.Command{
		Use:   "delete <host-or-id-or-fingerprint>",
		Short: "Delete saved SSH host keys from vault and/or file backends",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, paths, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			deleted, err := service.DeleteKnownHostsEntries(cmd.Context(), catalog, paths.KnownHostsPath, args[0], source)
			if err != nil {
				return err
			}
			if deleted == 0 {
				return errors.New("no known host entries matched")
			}
			return printJSON(map[string]any{
				"deleted": deleted,
				"source":  source,
			})
		},
	}
	cmd.Flags().StringVar(&source, "source", "all", "Known host source: all, vault, file")
	return cmd
}
