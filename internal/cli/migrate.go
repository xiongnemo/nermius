package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nermius/nermius/internal/config"
)

func (r *runtime) newMigrateCmd() *cobra.Command {
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Move files older releases left behind to the XDG directories",
		Long: `Move the files older nermius releases left behind to the XDG directories.

nermius keeps the vault and the keychain enrollment blobs in
$XDG_DATA_HOME/nermius (default ~/.local/share/nermius) on every OS. Older
releases used ~/.nermius (v0.0.33-dev) and, before that, the OS config and
cache directories: %APPDATA%\nermius and %LOCALAPPDATA%\nermius on Windows,
~/Library/Application Support/nermius and ~/Library/Caches/nermius on macOS,
and ~/.config/nermius and ~/.cache/nermius elsewhere. Until you migrate,
nermius keeps using what it finds there and says so on stderr.

migrate never overwrites a file. If the new location already holds one, an
identical old copy is removed; a different one stays where it is, the conflict
is reported, and migrate exits non-zero once it has done everything else.
A vault's SQLite journal files move only together with it; when the vault
stays, they stay with it. Empty old directories are removed afterwards. session.json files from the
earliest releases hold a plaintext copy of the vault key; they are deleted,
not moved. Run migrate again after it has finished and it finds nothing to do.

migrate only looks at the default locations; --vault does not change what it
moves. It cannot tell whether another nermius is running, so close every
nermius (the TUI, connect, forward start) before you run it.`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			env, err := config.CurrentEnv()
			if err != nil {
				return err
			}
			return runMigrate(cmd.OutOrStdout(), env, config.ExpandUser(strings.TrimSpace(r.vaultPath)), dryRun)
		},
	}
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print every move and skip without changing anything")
	return cmd
}

func runMigrate(out io.Writer, env config.Env, vaultOverride string, dryRun bool) error {
	plan := config.PlanMigration(env)
	fmt.Fprintf(out, "Old locations checked: %s\n", strings.Join(plan.Checked, ", "))
	fmt.Fprintf(out, "New data directory: %s\n", plan.Dirs.Data)
	if !plan.Pending() && plan.Conflicts() == 0 {
		for _, action := range plan.Actions {
			fmt.Fprintln(out, config.DescribePlanned(action))
		}
		fmt.Fprintln(out, "Nothing to migrate.")
		return nil
	}
	if vaultOverride != "" {
		if absolute, err := filepath.Abs(vaultOverride); err == nil {
			vaultOverride = absolute
		}
		if to, moved := plan.Moves(vaultOverride); moved {
			defer fmt.Fprintf(out, "Note: --vault points at %s, which migrate moves to %s. Pass the new path from now on.\n", vaultOverride, to)
		}
	}
	if dryRun {
		fmt.Fprintln(out, "Dry run: nothing will be changed.")
		for _, action := range plan.Actions {
			fmt.Fprintln(out, config.DescribePlanned(action))
		}
		if conflicts := plan.Conflicts(); conflicts > 0 {
			fmt.Fprintf(out, "%d conflict(s) would be left for you to resolve.\n", conflicts)
		}
		return nil
	}
	result := plan.Execute(out)
	if result.Conflicts == 0 && result.Failures == 0 {
		fmt.Fprintln(out, "Migration complete.")
		return nil
	}
	parts := []string{}
	if result.Conflicts > 0 {
		parts = append(parts, fmt.Sprintf("%d conflict(s): both copies were kept; compare each pair, keep the one you want at the new location, delete the other, then run \"nermius migrate\" again", result.Conflicts))
	}
	if result.Failures > 0 {
		parts = append(parts, fmt.Sprintf("%d action(s) failed; see above", result.Failures))
	}
	return fmt.Errorf("migrate: %s", strings.Join(parts, "; "))
}
