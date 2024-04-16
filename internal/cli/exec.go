package cli

import (
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nermius/nermius/internal/service"
)

func (r *runtime) newExecCmd() *cobra.Command {
	var localSpecs, remoteSpecs, dynamicSpecs []string
	cmd := &cobra.Command{
		Use:   "exec <host> <command>",
		Short: "Run a remote command on a resolved host",
		Args:  cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, paths, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()

			connector := service.NewConnector(catalog, paths.KnownHostsPath)
			connector.Verbosity = r.verbose
			extraForwards, err := parseCLIForwards(localSpecs, remoteSpecs, dynamicSpecs)
			if err != nil {
				return err
			}
			return connector.Exec(
				cmd.Context(),
				args[0],
				joinExecCommand(args[1:]),
				service.Prompts{
					Text:    promptText,
					Secret:  promptSecret,
					Confirm: promptConfirm,
				},
				extraForwards,
				os.Stdin,
				os.Stdout,
				os.Stderr,
			)
		},
	}
	cmd.Flags().StringArrayVarP(&localSpecs, "local", "L", nil, "One-time local forward (LISTEN_HOST:LISTEN_PORT:TARGET_HOST:TARGET_PORT or LISTEN_PORT:TARGET_HOST:TARGET_PORT)")
	cmd.Flags().StringArrayVarP(&remoteSpecs, "remote", "R", nil, "One-time remote forward")
	cmd.Flags().StringArrayVarP(&dynamicSpecs, "dynamic", "D", nil, "One-time dynamic forward (LISTEN_HOST:LISTEN_PORT or LISTEN_PORT)")
	return cmd
}

func joinExecCommand(args []string) string {
	return strings.Join(args, " ")
}
