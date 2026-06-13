package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/termius"
)

func (r *runtime) newTermiusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "termius",
		Short: "Export Termius local data and import credentials",
		Long: `Export Termius local data and import normalized credentials.

Local Termius decryption currently reads the Termius localKey from Windows
Credential Manager. Linux and macOS local Termius export/import-from-local are
not supported yet.`,
	}
	cmd.AddCommand(
		r.newTermiusExportCmd(),
		r.newTermiusImportCmd(),
	)
	return cmd
}

func (r *runtime) newTermiusExportCmd() *cobra.Command {
	var (
		sourceDir      string
		outPath        string
		includeSecrets bool
		rawOnly        bool
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all decryptable Termius JSON objects",
		Long: `Export all locally decryptable Termius data.

This command currently supports local Termius decryption only on Windows because
it reads the Termius localKey from Windows Credential Manager. Linux and macOS
support is not implemented yet.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if includeSecrets {
				fmt.Fprintln(cmd.ErrOrStderr(), "warning: Termius export contains passwords, private keys, passphrases, and scripts")
			}
			bundle, err := termius.ExportLocal(cmd.Context(), termius.ExportOptions{
				SourceDir:      config.ExpandUser(sourceDir),
				IncludeSecrets: includeSecrets,
				RawOnly:        rawOnly,
			})
			if err != nil {
				return err
			}
			if strings.TrimSpace(outPath) == "" {
				return printJSON(bundle)
			}
			return writeJSONFile(outPath, bundle)
		},
	}
	cmd.Flags().StringVar(&sourceDir, "source-dir", termius.DefaultDataRoot(), "Termius data root or a specific LevelDB directory")
	cmd.Flags().StringVar(&outPath, "out", "", "Write export bundle to file instead of stdout")
	cmd.Flags().BoolVar(&includeSecrets, "include-secrets", false, "Include decrypted passwords, private keys, passphrases, scripts, and raw object values")
	cmd.Flags().BoolVar(&rawOnly, "raw-only", false, "Only write raw_objects and skip normalized import views")
	return cmd
}

func (r *runtime) newTermiusImportCmd() *cobra.Command {
	var (
		filePath  string
		fromLocal bool
		dryRun    bool
		conflict  string
		sourceDir string
	)
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import normalized Termius credentials into the Nermius vault",
		Long: `Import normalized Termius credentials into the Nermius vault.

Importing from an existing export file works on any supported Nermius platform.
The --from-local path currently supports local Termius decryption only on
Windows because it reads the Termius localKey from Windows Credential Manager.
Linux and macOS --from-local support is not implemented yet.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromLocal == (strings.TrimSpace(filePath) != "") {
				return errors.New("choose exactly one of --file or --from-local")
			}
			mode, err := parseTermiusConflictMode(conflict)
			if err != nil {
				return err
			}
			var bundle termius.Bundle
			if fromLocal {
				bundle, err = termius.ExportLocal(cmd.Context(), termius.ExportOptions{
					SourceDir:      config.ExpandUser(sourceDir),
					IncludeSecrets: true,
				})
			} else {
				bundle, err = readTermiusBundle(filePath)
			}
			if err != nil {
				return err
			}
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			importer := service.NewTermiusImporter(catalog)
			report, err := importer.Import(cmd.Context(), bundle, service.TermiusImportOptions{
				DryRun:   dryRun,
				Conflict: mode,
			})
			if err != nil {
				return err
			}
			return printJSON(report)
		},
	}
	cmd.Flags().StringVar(&filePath, "file", "", "Read a Termius export bundle from file")
	cmd.Flags().BoolVar(&fromLocal, "from-local", false, "Read and decrypt the local Termius database directly")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Report import actions without writing to the vault")
	cmd.Flags().StringVar(&conflict, "conflict", string(service.TermiusConflictRename), "Conflict handling: skip, rename, overwrite")
	cmd.Flags().StringVar(&sourceDir, "source-dir", termius.DefaultDataRoot(), "Termius data root or a specific LevelDB directory for --from-local")
	return cmd
}

func parseTermiusConflictMode(raw string) (service.TermiusConflictMode, error) {
	switch service.TermiusConflictMode(strings.ToLower(strings.TrimSpace(raw))) {
	case service.TermiusConflictSkip:
		return service.TermiusConflictSkip, nil
	case service.TermiusConflictRename, "":
		return service.TermiusConflictRename, nil
	case service.TermiusConflictOverwrite:
		return service.TermiusConflictOverwrite, nil
	default:
		return "", fmt.Errorf("unsupported conflict mode %q", raw)
	}
}

func readTermiusBundle(path string) (termius.Bundle, error) {
	raw, err := os.ReadFile(config.ExpandUser(path))
	if err != nil {
		return termius.Bundle{}, err
	}
	var bundle termius.Bundle
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bundle); err != nil {
		return termius.Bundle{}, err
	}
	if bundle.Source != termius.SourceName {
		return termius.Bundle{}, fmt.Errorf("unsupported bundle source %q", bundle.Source)
	}
	if bundle.FormatVersion != termius.BundleFormatVersion {
		return termius.Bundle{}, fmt.Errorf("unsupported Termius bundle format version %d", bundle.FormatVersion)
	}
	return bundle, nil
}

func writeJSONFile(path string, value any) error {
	path = config.ExpandUser(path)
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return config.EnsurePrivateFile(path, append(raw, '\n'))
}
