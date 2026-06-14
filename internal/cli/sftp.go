package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/nermius/nermius/internal/service"
)

type sftpCLIOptions struct {
	json      bool
	force     bool
	parents   bool
	recursive bool
}

func (r *runtime) newSFTPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sftp",
		Short: "Browse and transfer files over SFTP",
	}
	cmd.AddCommand(
		r.newSFTPListCmd(),
		r.newSFTPStatCmd(),
		r.newSFTPGetCmd(),
		r.newSFTPPutCmd(),
		r.newSFTPMkdirCmd(),
		r.newSFTPRmCmd(),
		r.newSFTPRenameCmd(),
	)
	return cmd
}

func (r *runtime) newSFTPListCmd() *cobra.Command {
	var opts sftpCLIOptions
	cmd := &cobra.Command{
		Use:   "ls <host>:<remote-path>",
		Short: "List a remote directory over SFTP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[0])
			if err != nil {
				return err
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			entries, err := session.ReadDir(cmd.Context(), spec.Path)
			if err != nil {
				return err
			}
			if opts.json {
				return printJSON(entries)
			}
			return printSFTPEntries(cmd, entries)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "Print entries as JSON")
	return cmd
}

func (r *runtime) newSFTPStatCmd() *cobra.Command {
	var opts sftpCLIOptions
	cmd := &cobra.Command{
		Use:   "stat <host>:<remote-path>",
		Short: "Show remote file metadata over SFTP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[0])
			if err != nil {
				return err
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			entry, err := session.Stat(cmd.Context(), spec.Path)
			if err != nil {
				return err
			}
			if opts.json {
				return printJSON(entry)
			}
			return printSFTPStat(cmd, entry)
		},
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "Print metadata as JSON")
	return cmd
}

func (r *runtime) newSFTPGetCmd() *cobra.Command {
	var opts sftpCLIOptions
	cmd := &cobra.Command{
		Use:   "get <host>:<remote-path> <local-path>",
		Short: "Download a remote file over SFTP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[0])
			if err != nil {
				return err
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			overwrite := opts.force
			if !overwrite {
				destination, exists, err := localDownloadPreview(spec.Path, args[1])
				if err != nil {
					return err
				}
				if exists {
					overwrite, err = promptSFTPOverwrite(destination)
					if err != nil {
						return err
					}
					if !overwrite {
						return &service.SFTPPathExistsError{Path: destination}
					}
				}
			}
			report, err := session.Download(cmd.Context(), spec.Path, args[1], overwrite)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Downloaded %s to %s (%d bytes)\n", report.Source, report.Destination, report.Bytes)
			return err
		},
	}
	cmd.Flags().BoolVar(&opts.force, "force", false, "Overwrite the local destination without prompting")
	return cmd
}

func (r *runtime) newSFTPPutCmd() *cobra.Command {
	var opts sftpCLIOptions
	cmd := &cobra.Command{
		Use:   "put <local-path> <host>:<remote-path>",
		Short: "Upload a local file over SFTP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[1])
			if err != nil {
				return err
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			report, err := session.Upload(cmd.Context(), args[0], spec.Path, opts.force)
			if errors.Is(err, service.ErrSFTPDestinationExists) && !opts.force {
				approved, confirmErr := promptSFTPOverwrite(extractSFTPExistsPath(err))
				if confirmErr != nil {
					return confirmErr
				}
				if !approved {
					return err
				}
				report, err = session.Upload(cmd.Context(), args[0], spec.Path, true)
			}
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Uploaded %s to %s (%d bytes)\n", report.Source, report.Destination, report.Bytes)
			return err
		},
	}
	cmd.Flags().BoolVar(&opts.force, "force", false, "Overwrite the remote destination without prompting")
	return cmd
}

func (r *runtime) newSFTPMkdirCmd() *cobra.Command {
	var opts sftpCLIOptions
	cmd := &cobra.Command{
		Use:   "mkdir <host>:<remote-path>",
		Short: "Create a remote directory over SFTP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[0])
			if err != nil {
				return err
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			if err := session.Mkdir(cmd.Context(), spec.Path, opts.parents); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Created %s\n", spec.Path)
			return err
		},
	}
	cmd.Flags().BoolVarP(&opts.parents, "parents", "p", false, "Create parent directories as needed")
	return cmd
}

func (r *runtime) newSFTPRmCmd() *cobra.Command {
	var opts sftpCLIOptions
	cmd := &cobra.Command{
		Use:   "rm <host>:<remote-path>",
		Short: "Remove a remote file or directory over SFTP",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[0])
			if err != nil {
				return err
			}
			if !opts.force {
				approved, err := confirmSFTPDelete(spec.Path, opts.recursive)
				if err != nil {
					return err
				}
				if !approved {
					return errors.New("remote delete canceled")
				}
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			if err := session.Remove(cmd.Context(), spec.Path, opts.recursive); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Removed %s\n", spec.Path)
			return err
		},
	}
	cmd.Flags().BoolVarP(&opts.recursive, "recursive", "r", false, "Remove directories recursively")
	cmd.Flags().BoolVar(&opts.force, "force", false, "Remove without prompting")
	return cmd
}

func (r *runtime) newSFTPRenameCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rename <host>:<old-path> <new-path>",
		Short: "Rename a remote path over SFTP",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			spec, err := service.ParseSFTPRemoteSpec(args[0])
			if err != nil {
				return err
			}
			session, closeDB, err := r.openSFTPSession(cmd, spec.Host)
			if err != nil {
				return err
			}
			defer closeDB()
			defer session.Close()
			newPath := service.NormalizeSFTPRemotePath(args[1])
			if err := session.Rename(cmd.Context(), spec.Path, newPath); err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Renamed %s to %s\n", spec.Path, newPath)
			return err
		},
	}
	return cmd
}

func (r *runtime) openSFTPSession(cmd *cobra.Command, host string) (*service.SFTPSession, func(), error) {
	catalog, db, paths, err := r.openCatalog(cmd.Context())
	if err != nil {
		return nil, nil, err
	}
	closeDB := func() { _ = db.Close() }
	connector := service.NewConnector(catalog, paths.KnownHostsPath)
	connector.Verbosity = r.verbose
	session, err := connector.OpenSFTP(cmd.Context(), host, service.Prompts{
		Text:     promptText,
		Secret:   promptSecret,
		Confirm:  promptConfirm,
		Progress: cliProgress(r.verbose, cmd.ErrOrStderr()),
	})
	if err != nil {
		closeDB()
		return nil, nil, err
	}
	return session, closeDB, nil
}

func printSFTPEntries(cmd *cobra.Command, entries []service.SFTPEntry) error {
	for _, entry := range entries {
		kind := "-"
		if entry.IsDir {
			kind = "d"
		}
		if _, err := fmt.Fprintf(
			cmd.OutOrStdout(),
			"%s %10d %-11s %s %s\n",
			kind,
			entry.Size,
			entry.Mode,
			entry.ModTime.Format(time.DateTime),
			entry.Name,
		); err != nil {
			return err
		}
	}
	return nil
}

func printSFTPStat(cmd *cobra.Command, entry service.SFTPEntry) error {
	kind := "file"
	if entry.IsDir {
		kind = "directory"
	}
	_, err := fmt.Fprintf(
		cmd.OutOrStdout(),
		"name: %s\npath: %s\ntype: %s\nsize: %d\nmode: %s\nmodified: %s\n",
		entry.Name,
		entry.Path,
		kind,
		entry.Size,
		entry.Mode,
		entry.ModTime.Format(time.RFC3339),
	)
	return err
}

func promptSFTPOverwrite(path string) (bool, error) {
	if path == "" {
		path = "destination"
	}
	return confirmSFTPAction("Overwrite " + path)
}

func confirmSFTPDelete(remotePath string, recursive bool) (bool, error) {
	label := "Remove remote path " + remotePath
	if recursive {
		label = "Recursively remove remote path " + remotePath
	}
	return confirmSFTPAction(label)
}

func confirmSFTPAction(label string) (bool, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return false, errors.New("confirmation requires an interactive terminal; pass --force to skip the prompt")
	}
	return promptConfirm(label)
}

func extractSFTPExistsPath(err error) string {
	var existsErr *service.SFTPPathExistsError
	if errors.As(err, &existsErr) {
		return existsErr.Path
	}
	return "destination"
}

func localDownloadPreview(remotePath, localPath string) (string, bool, error) {
	info, err := os.Stat(localPath)
	if err == nil && info.IsDir() {
		destination := filepath.Join(localPath, service.BaseSFTPRemotePath(remotePath))
		if _, err := os.Stat(destination); err == nil {
			return destination, true, nil
		} else if err != nil && !os.IsNotExist(err) {
			return "", false, err
		}
		return destination, false, nil
	}
	if err == nil {
		return localPath, true, nil
	}
	if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	return localPath, false, nil
}
