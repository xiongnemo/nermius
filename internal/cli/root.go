package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/nermius/nermius/internal/buildinfo"
	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
	"github.com/nermius/nermius/internal/store"
	"github.com/nermius/nermius/internal/tui"
)

type runtime struct {
	vaultPath string
	verbose   int
}

func Execute() error {
	rt := &runtime{}
	return newRootCommand(rt).Execute()
}

func newRootCommand(rt *runtime) *cobra.Command {
	info := buildinfo.Current()
	root := &cobra.Command{
		Use:   "nermius",
		Short: "Portable SSH manager with CLI and TUI workflows",
		Long: fmt.Sprintf(
			"Portable SSH manager with CLI and TUI workflows\n\nVersion: %s\nBuild Time: %s",
			info.Version,
			info.BuildTime,
		),
	}
	root.PersistentFlags().StringVar(&rt.vaultPath, "vault", "", "Path to vault SQLite file")
	root.PersistentFlags().CountVarP(&rt.verbose, "verbose", "v", "Increase debug verbosity (-v, -vv, -vvv)")
	root.AddCommand(
		rt.newVersionCmd(),
		rt.newVaultCmd(),
		rt.newInstallCmd(),
		rt.newKnownHostsCmd(),
		rt.newResourceCmd(domain.KindHost),
		rt.newResourceCmd(domain.KindGroup),
		rt.newResourceCmd(domain.KindProfile),
		rt.newResourceCmd(domain.KindIdentity),
		rt.newResourceCmd(domain.KindKey),
		rt.newResourceCmd(domain.KindForward),
		rt.newInspectCmd(),
		rt.newImportCmd(),
		rt.newConnectCmd(),
		rt.newExecCmd(),
		rt.newTUICmd(),
	)
	return root
}

func (r *runtime) paths() (config.Paths, error) {
	return config.ResolvePaths(r.vaultPath)
}

func (r *runtime) manager() (*service.VaultManager, error) {
	paths, err := r.paths()
	if err != nil {
		return nil, err
	}
	return service.NewVaultManager(paths), nil
}

func (r *runtime) openStore(ctx context.Context) (*store.Store, *service.VaultManager, error) {
	manager, err := r.manager()
	if err != nil {
		return nil, nil, err
	}
	db, err := manager.Open(ctx)
	if err != nil {
		return nil, nil, err
	}
	return db, manager, nil
}

func (r *runtime) openCatalog(ctx context.Context) (*service.Catalog, *store.Store, config.Paths, error) {
	manager, err := r.manager()
	if err != nil {
		return nil, nil, config.Paths{}, err
	}
	masterKey, db, err := manager.ResolveMasterKey(ctx, promptSecret)
	if err != nil {
		return nil, nil, config.Paths{}, err
	}
	return service.NewCatalog(db, masterKey), db, manager.Paths, nil
}

func (r *runtime) newVaultCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vault",
		Short: "Manage the local vault lifecycle",
	}
	cmd.AddCommand(
		r.newVaultInitCmd(),
		r.newVaultUnlockCmd(),
		r.newVaultLockCmd(),
		r.newVaultChangePasswordCmd(),
	)
	return cmd
}

func (r *runtime) newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the current build version",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), buildinfo.Current().Version)
			return err
		},
	}
}

func (r *runtime) newVaultInitCmd() *cobra.Command {
	var password string
	var mode interactiveMode
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize a new vault",
		RunE: func(cmd *cobra.Command, args []string) error {
			if mode.Enabled() {
				paths, err := r.paths()
				if err != nil {
					return err
				}
				vaultPath, err := promptLine("Vault path", paths.VaultPath, true)
				if err != nil {
					return err
				}
				r.vaultPath = vaultPath
			}
			if password == "" || mode.Enabled() {
				first, err := promptSecret("New master password")
				if err != nil {
					return err
				}
				second, err := promptSecret("Confirm master password")
				if err != nil {
					return err
				}
				if first != second {
					return errors.New("passwords do not match")
				}
				password = first
			}
			manager, err := r.manager()
			if err != nil {
				return err
			}
			return manager.Init(cmd.Context(), password)
		},
	}
	cmd.Flags().StringVar(&password, "password", "", "Master password (avoid passing on shared shells)")
	bindInteractiveFlags(cmd, &mode)
	return cmd
}

func (r *runtime) newVaultUnlockCmd() *cobra.Command {
	var password string
	var ttl time.Duration
	cmd := &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault and cache a session key locally",
		RunE: func(cmd *cobra.Command, args []string) error {
			if password == "" {
				value, err := promptSecret("Master password")
				if err != nil {
					return err
				}
				password = value
			}
			manager, err := r.manager()
			if err != nil {
				return err
			}
			return manager.Unlock(cmd.Context(), password, ttl)
		},
	}
	cmd.Flags().StringVar(&password, "password", "", "Master password")
	cmd.Flags().DurationVar(&ttl, "ttl", 8*time.Hour, "Session cache TTL")
	return cmd
}

func (r *runtime) newVaultLockCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "lock",
		Short: "Remove the cached session key",
		RunE: func(cmd *cobra.Command, args []string) error {
			manager, err := r.manager()
			if err != nil {
				return err
			}
			return manager.Lock()
		},
	}
}

func (r *runtime) newVaultChangePasswordCmd() *cobra.Command {
	var oldPassword, newPassword string
	cmd := &cobra.Command{
		Use:   "change-password",
		Short: "Rotate the vault master password",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			if oldPassword == "" {
				oldPassword, err = promptSecret("Current master password")
				if err != nil {
					return err
				}
			}
			if newPassword == "" {
				first, err := promptSecret("New master password")
				if err != nil {
					return err
				}
				second, err := promptSecret("Confirm new master password")
				if err != nil {
					return err
				}
				if first != second {
					return errors.New("passwords do not match")
				}
				newPassword = first
			}
			manager, err := r.manager()
			if err != nil {
				return err
			}
			return manager.ChangePassword(cmd.Context(), oldPassword, newPassword)
		},
	}
	cmd.Flags().StringVar(&oldPassword, "old-password", "", "Existing master password")
	cmd.Flags().StringVar(&newPassword, "new-password", "", "New master password")
	return cmd
}

func (r *runtime) newResourceCmd(kind domain.DocumentKind) *cobra.Command {
	cmd := &cobra.Command{
		Use:   string(kind),
		Short: fmt.Sprintf("Manage %s", pluralizeKind(kind)),
	}
	cmd.AddCommand(
		r.newCreateCmd(kind),
		r.newPutCmd(kind),
		r.newGetCmd(kind),
		r.newListCmd(kind),
		r.newDeleteCmd(kind),
	)
	return cmd
}

func (r *runtime) newPutCmd(kind domain.DocumentKind) *cobra.Command {
	var file string
	var mode interactiveMode
	cmd := &cobra.Command{
		Use:   "put",
		Short: fmt.Sprintf("Create or update a %s from JSON", kind),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			if mode.Enabled() {
				if file != "" {
					return errors.New("--file cannot be used with -it")
				}
				value, err := buildInteractiveDocument(cmd.Context(), catalog, kind)
				if err != nil {
					return err
				}
				return saveDocumentAndPrint(cmd.Context(), catalog, kind, value)
			}
			switch kind {
			case domain.KindHost:
				var value domain.Host
				if err := readJSON(file, &value); err != nil {
					return err
				}
				if err := catalog.SaveHost(cmd.Context(), &value); err != nil {
					return err
				}
				return printJSON(value)
			case domain.KindGroup:
				var value domain.Group
				if err := readJSON(file, &value); err != nil {
					return err
				}
				if err := catalog.SaveGroup(cmd.Context(), &value); err != nil {
					return err
				}
				return printJSON(value)
			case domain.KindProfile:
				var value domain.Profile
				if err := readJSON(file, &value); err != nil {
					return err
				}
				if err := catalog.SaveProfile(cmd.Context(), &value); err != nil {
					return err
				}
				return printJSON(value)
			case domain.KindIdentity:
				var value domain.Identity
				if err := readJSON(file, &value); err != nil {
					return err
				}
				if err := catalog.SaveIdentity(cmd.Context(), &value); err != nil {
					return err
				}
				return printJSON(value)
			case domain.KindKey:
				var value domain.Key
				if err := readJSON(file, &value); err != nil {
					return err
				}
				if err := catalog.SaveKey(cmd.Context(), &value); err != nil {
					return err
				}
				return printJSON(value)
			case domain.KindForward:
				var value domain.Forward
				if err := readJSON(file, &value); err != nil {
					return err
				}
				if err := catalog.SaveForward(cmd.Context(), &value); err != nil {
					return err
				}
				return printJSON(value)
			default:
				return fmt.Errorf("unsupported kind %s", kind)
			}
		},
	}
	cmd.Flags().StringVar(&file, "file", "", "Read JSON from file instead of stdin")
	bindInteractiveFlags(cmd, &mode)
	return cmd
}

func (r *runtime) newCreateCmd(kind domain.DocumentKind) *cobra.Command {
	var (
		title             string
		hostname          string
		port              int
		username          string
		groupSpecs        []string
		profileSpecs      []string
		identitySpec      string
		keySpec           string
		password          string
		forwardSpecs      []string
		knownHostsPolicy  string
		knownHostsBackend string
		knownHostsPath    string
		jumps             []string
		socks5Proxy       string
		httpProxy         string
		proxyUsername     string
		proxyPassword     string
		mode              interactiveMode
	)
	cmd := &cobra.Command{
		Use:     "add",
		Aliases: []string{"create", "new"},
		Short:   fmt.Sprintf("Add a new %s", kind),
		Example: strings.TrimSpace(`
nermius host add --hostname prod.example.com
nermius host add --title prod --hostname prod.example.com --identity ops --profile default
nermius host add --title prod --hostname prod.example.com --identity ops --key deploy-key
nermius host add --title bastion --hostname bastion.example.com --jump corp-gateway --known-hosts accept-new
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			if kind != domain.KindHost {
				if !mode.Enabled() {
					return fmt.Errorf("use `%s add -it` for interactive creation or `%s put` for JSON input", kind, kind)
				}
				value, err := buildInteractiveDocument(cmd.Context(), catalog, kind)
				if err != nil {
					return err
				}
				return saveDocumentAndPrint(cmd.Context(), catalog, kind, value)
			}

			if mode.Enabled() {
				defaults := domain.Host{
					Title:    strings.TrimSpace(title),
					Hostname: strings.TrimSpace(hostname),
					Route:    nil,
				}
				if port > 0 {
					defaults.Port = intPtr(port)
				}
				if strings.TrimSpace(username) != "" {
					defaults.Username = stringPtr(strings.TrimSpace(username))
				}
				if len(groupSpecs) > 0 {
					groupIDs, err := resolveSpecsToIDs(cmd.Context(), catalog, domain.KindGroup, groupSpecs)
					if err != nil {
						return err
					}
					defaults.GroupIDs = groupIDs
				}
				if len(profileSpecs) > 0 {
					profileIDs, err := resolveSpecsToIDs(cmd.Context(), catalog, domain.KindProfile, profileSpecs)
					if err != nil {
						return err
					}
					defaults.ProfileIDs = profileIDs
				}
				if strings.TrimSpace(identitySpec) != "" {
					identityID, err := catalog.ResolveDocumentID(cmd.Context(), domain.KindIdentity, identitySpec)
					if err != nil {
						return err
					}
					defaults.IdentityRef = &identityID
				}
				if strings.TrimSpace(keySpec) != "" {
					keyID, err := catalog.ResolveDocumentID(cmd.Context(), domain.KindKey, keySpec)
					if err != nil {
						return err
					}
					defaults.KeyRef = &keyID
				}
				if strings.TrimSpace(password) != "" {
					defaults.Password = password
				}
				if len(forwardSpecs) > 0 {
					forwardIDs, err := resolveSpecsToIDs(cmd.Context(), catalog, domain.KindForward, forwardSpecs)
					if err != nil {
						return err
					}
					defaults.ForwardIDs = forwardIDs
				}
				knownHostsCfg, err := buildKnownHostsConfig(knownHostsPolicy, knownHostsBackend, knownHostsPath)
				if err != nil {
					return err
				}
				if knownHostsCfg != nil {
					defaults.KnownHosts = knownHostsCfg
				}
				if len(jumps) > 0 || strings.TrimSpace(socks5Proxy) != "" || strings.TrimSpace(httpProxy) != "" {
					defaults.Route = &domain.Route{
						ProxyJump: append([]string(nil), jumps...),
					}
					if strings.TrimSpace(socks5Proxy) != "" || strings.TrimSpace(httpProxy) != "" {
						if strings.TrimSpace(socks5Proxy) != "" && strings.TrimSpace(httpProxy) != "" {
							return errors.New("choose only one of --proxy-socks5 or --proxy-http")
						}
						proxyType := domain.ProxySOCKS5
						address := strings.TrimSpace(socks5Proxy)
						if strings.TrimSpace(httpProxy) != "" {
							proxyType = domain.ProxyHTTP
							address = strings.TrimSpace(httpProxy)
						}
						defaults.Route.OutboundProxy = &domain.OutboundProxy{
							Type:     proxyType,
							Address:  address,
							Username: strings.TrimSpace(proxyUsername),
							Password: proxyPassword,
						}
					}
				}
				host, err := promptHostInteractive(cmd.Context(), catalog, defaults)
				if err != nil {
					return err
				}
				if err := catalog.SaveHost(cmd.Context(), &host); err != nil {
					return err
				}
				return printJSON(host)
			}

			host := domain.Host{
				Title:    strings.TrimSpace(title),
				Hostname: strings.TrimSpace(hostname),
			}
			if host.Hostname == "" {
				return errors.New("hostname is required")
			}
			if port > 0 {
				host.Port = intPtr(port)
			}
			if strings.TrimSpace(username) != "" {
				host.Username = stringPtr(strings.TrimSpace(username))
			}
			groupIDs, err := resolveSpecsToIDs(cmd.Context(), catalog, domain.KindGroup, groupSpecs)
			if err != nil {
				return err
			}
			host.GroupIDs = groupIDs
			profileIDs, err := resolveSpecsToIDs(cmd.Context(), catalog, domain.KindProfile, profileSpecs)
			if err != nil {
				return err
			}
			host.ProfileIDs = profileIDs
			forwardIDs, err := resolveSpecsToIDs(cmd.Context(), catalog, domain.KindForward, forwardSpecs)
			if err != nil {
				return err
			}
			host.ForwardIDs = forwardIDs
			if strings.TrimSpace(identitySpec) != "" {
				identityID, err := catalog.ResolveDocumentID(cmd.Context(), domain.KindIdentity, identitySpec)
				if err != nil {
					return err
				}
				host.IdentityRef = &identityID
			}
			if strings.TrimSpace(keySpec) != "" {
				keyID, err := catalog.ResolveDocumentID(cmd.Context(), domain.KindKey, keySpec)
				if err != nil {
					return err
				}
				host.KeyRef = &keyID
			}
			if strings.TrimSpace(password) != "" {
				host.Password = password
			}
			host.KnownHosts, err = buildKnownHostsConfig(knownHostsPolicy, knownHostsBackend, knownHostsPath)
			if err != nil {
				return err
			}
			if len(jumps) > 0 || strings.TrimSpace(socks5Proxy) != "" || strings.TrimSpace(httpProxy) != "" {
				host.Route = &domain.Route{
					ProxyJump: append([]string(nil), jumps...),
				}
				if strings.TrimSpace(socks5Proxy) != "" || strings.TrimSpace(httpProxy) != "" {
					if strings.TrimSpace(socks5Proxy) != "" && strings.TrimSpace(httpProxy) != "" {
						return errors.New("choose only one of --proxy-socks5 or --proxy-http")
					}
					proxyType := domain.ProxySOCKS5
					address := strings.TrimSpace(socks5Proxy)
					if strings.TrimSpace(httpProxy) != "" {
						proxyType = domain.ProxyHTTP
						address = strings.TrimSpace(httpProxy)
					}
					host.Route.OutboundProxy = &domain.OutboundProxy{
						Type:     proxyType,
						Address:  address,
						Username: strings.TrimSpace(proxyUsername),
						Password: proxyPassword,
					}
				}
			}
			if err := catalog.SaveHost(cmd.Context(), &host); err != nil {
				return err
			}
			return printJSON(host)
		},
	}
	bindInteractiveFlags(cmd, &mode)
	if kind != domain.KindHost {
		cmd.Example = strings.TrimSpace(fmt.Sprintf(`
nermius %s add -it
		`, kind))
		return cmd
	}
	cmd.Flags().StringVar(&title, "title", "", "Friendly host name")
	cmd.Flags().StringVar(&hostname, "hostname", "", "SSH hostname or IP address")
	cmd.Flags().IntVar(&port, "port", 0, "SSH port override")
	cmd.Flags().StringVar(&username, "username", "", "Username override on the host")
	cmd.Flags().StringSliceVar(&groupSpecs, "group", nil, "Group name or ID to attach")
	cmd.Flags().StringSliceVar(&profileSpecs, "profile", nil, "Profile name or ID to apply in order")
	cmd.Flags().StringVar(&identitySpec, "identity", "", "Identity name or ID")
	cmd.Flags().StringVar(&keySpec, "key", "", "Direct key override by name or ID")
	cmd.Flags().StringVar(&password, "password", "", "Direct password override")
	cmd.Flags().StringSliceVar(&forwardSpecs, "forward", nil, "Forward name or ID")
	cmd.Flags().StringVar(&knownHostsPolicy, "known-hosts", "", "Known hosts policy: strict, accept-new, off")
	cmd.Flags().StringVar(&knownHostsBackend, "known-hosts-backend", "", "Known hosts backend: vault, file, vault+file, file+vault")
	cmd.Flags().StringVar(&knownHostsPath, "known-hosts-path", "", "Known hosts file path override")
	cmd.Flags().StringSliceVar(&jumps, "jump", nil, "Jump host chain entry (host name/ID or raw user@host:port)")
	cmd.Flags().StringVar(&socks5Proxy, "proxy-socks5", "", "Outbound SOCKS5 proxy address")
	cmd.Flags().StringVar(&httpProxy, "proxy-http", "", "Outbound HTTP CONNECT proxy address")
	cmd.Flags().StringVar(&proxyUsername, "proxy-username", "", "Outbound proxy username")
	cmd.Flags().StringVar(&proxyPassword, "proxy-password", "", "Outbound proxy password")
	return cmd
}

func (r *runtime) newGetCmd(kind domain.DocumentKind) *cobra.Command {
	return &cobra.Command{
		Use:   "get <name-or-id>",
		Short: fmt.Sprintf("Get a %s by name, full ID, or unique short ID", kind),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, _, err := r.openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			catalog := service.NewCatalog(db, nil)
			rec, err := catalog.ResolveDocument(cmd.Context(), kind, args[0])
			if err != nil {
				return err
			}
			_, err = os.Stdout.Write(append(rec.Body, '\n'))
			return err
		},
	}
}

func (r *runtime) newListCmd(kind domain.DocumentKind) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: fmt.Sprintf("List %s", pluralizeKind(kind)),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, _, err := r.openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			items, err := db.ListDocuments(cmd.Context(), string(kind))
			if err != nil {
				return err
			}
			return printJSON(items)
		},
	}
}

func (r *runtime) newDeleteCmd(kind domain.DocumentKind) *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name-or-id>",
		Short: fmt.Sprintf("Delete a %s by name, full ID, or unique short ID", kind),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			db, _, err := r.openStore(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			catalog := service.NewCatalog(db, nil)
			rec, err := catalog.ResolveDocument(cmd.Context(), kind, args[0])
			if err != nil {
				return err
			}
			return db.DeleteDocument(cmd.Context(), rec.ID)
		},
	}
}

func (r *runtime) newInspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <host>",
		Short: "Resolve a host and print the effective connection config",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			resolved, err := catalog.ResolveHost(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printJSON(resolved)
		},
	}
}

func (r *runtime) newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import external SSH configuration into the vault",
	}
	var configPath string
	home, _ := os.UserHomeDir()
	opensshCmd := &cobra.Command{
		Use:   "openssh",
		Short: "Import hosts from an OpenSSH config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, _, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			importer := service.NewOpenSSHImporter(catalog)
			report, err := importer.Import(cmd.Context(), configPath)
			if err != nil {
				return err
			}
			return printJSON(report)
		},
	}
	opensshCmd.Flags().StringVar(&configPath, "config", config.ExpandUser(home+"/.ssh/config"), "OpenSSH config file path")
	cmd.AddCommand(opensshCmd)
	return cmd
}

func (r *runtime) newConnectCmd() *cobra.Command {
	var localSpecs, remoteSpecs, dynamicSpecs []string
	cmd := &cobra.Command{
		Use:   "connect <host>",
		Short: "Open an SSH session to a resolved host",
		Args:  cobra.ExactArgs(1),
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
			return connector.ConnectInteractive(cmd.Context(), args[0], service.Prompts{
				Text:    promptText,
				Secret:  promptSecret,
				Confirm: promptConfirm,
			}, extraForwards)
		},
	}
	cmd.Flags().StringArrayVarP(&localSpecs, "local", "L", nil, "One-time local forward (LISTEN_HOST:LISTEN_PORT:TARGET_HOST:TARGET_PORT or LISTEN_PORT:TARGET_HOST:TARGET_PORT)")
	cmd.Flags().StringArrayVarP(&remoteSpecs, "remote", "R", nil, "One-time remote forward")
	cmd.Flags().StringArrayVarP(&dynamicSpecs, "dynamic", "D", nil, "One-time dynamic forward (LISTEN_HOST:LISTEN_PORT or LISTEN_PORT)")
	return cmd
}

func (r *runtime) newTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive management TUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			catalog, db, paths, err := r.openCatalog(cmd.Context())
			if err != nil {
				return err
			}
			defer db.Close()
			connector := service.NewConnector(catalog, paths.KnownHostsPath)
			connector.Verbosity = r.verbose
			return tui.Run(cmd.Context(), catalog, connector)
		},
	}
}

func readJSON(path string, out any) error {
	var raw []byte
	var err error
	if path == "" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(config.ExpandUser(path))
	}
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	return decoder.Decode(out)
}

func printJSON(value any) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(append(raw, '\n'))
	return err
}

func promptText(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	value, err := readPromptLine()
	if err != nil {
		return "", err
	}
	return value, nil
}

func promptSecret(label string) (string, error) {
	fmt.Fprintf(os.Stderr, "%s: ", label)
	value, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(value)), nil
}

func promptConfirm(label string) (bool, error) {
	for {
		fmt.Fprintf(os.Stderr, "%s [y/N]: ", label)
		value, err := readPromptLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(value) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "Please answer y or n.")
		}
	}
}

func readPromptLine() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func parseCLIForwards(localSpecs, remoteSpecs, dynamicSpecs []string) ([]domain.Forward, error) {
	out := []domain.Forward{}
	for _, spec := range localSpecs {
		forward, err := parseCLIForward(domain.ForwardLocal, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, forward)
	}
	for _, spec := range remoteSpecs {
		forward, err := parseCLIForward(domain.ForwardRemote, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, forward)
	}
	for _, spec := range dynamicSpecs {
		forward, err := parseCLIForward(domain.ForwardDynamic, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, forward)
	}
	return out, nil
}

func parseCLIForward(kind domain.ForwardType, spec string) (domain.Forward, error) {
	parts := strings.Split(spec, ":")
	switch kind {
	case domain.ForwardDynamic:
		switch len(parts) {
		case 1:
			port, err := strconv.Atoi(parts[0])
			if err != nil {
				return domain.Forward{}, err
			}
			return domain.Forward{Name: "runtime-dynamic-" + parts[0], Type: kind, ListenHost: "127.0.0.1", ListenPort: port, Enabled: true}, nil
		case 2:
			port, err := strconv.Atoi(parts[1])
			if err != nil {
				return domain.Forward{}, err
			}
			return domain.Forward{Name: "runtime-dynamic-" + spec, Type: kind, ListenHost: parts[0], ListenPort: port, Enabled: true}, nil
		default:
			return domain.Forward{}, fmt.Errorf("invalid dynamic forward %q", spec)
		}
	case domain.ForwardLocal, domain.ForwardRemote:
		var forward domain.Forward
		switch len(parts) {
		case 3:
			listenPort, err := strconv.Atoi(parts[0])
			if err != nil {
				return domain.Forward{}, err
			}
			targetPort, err := strconv.Atoi(parts[2])
			if err != nil {
				return domain.Forward{}, err
			}
			forward = domain.Forward{
				Name:       "runtime-" + string(kind) + "-" + spec,
				Type:       kind,
				ListenHost: "127.0.0.1",
				ListenPort: listenPort,
				TargetHost: parts[1],
				TargetPort: targetPort,
				Enabled:    true,
			}
		case 4:
			listenPort, err := strconv.Atoi(parts[1])
			if err != nil {
				return domain.Forward{}, err
			}
			targetPort, err := strconv.Atoi(parts[3])
			if err != nil {
				return domain.Forward{}, err
			}
			forward = domain.Forward{
				Name:       "runtime-" + string(kind) + "-" + spec,
				Type:       kind,
				ListenHost: parts[0],
				ListenPort: listenPort,
				TargetHost: parts[2],
				TargetPort: targetPort,
				Enabled:    true,
			}
		default:
			return domain.Forward{}, fmt.Errorf("invalid %s forward %q", kind, spec)
		}
		return forward, nil
	default:
		return domain.Forward{}, fmt.Errorf("unsupported forward type %s", kind)
	}
}

func saveDocumentAndPrint(ctx context.Context, catalog *service.Catalog, kind domain.DocumentKind, value any) error {
	switch kind {
	case domain.KindHost:
		host, ok := value.(domain.Host)
		if !ok {
			return errors.New("interactive host payload is invalid")
		}
		if err := catalog.SaveHost(ctx, &host); err != nil {
			return err
		}
		return printJSON(host)
	case domain.KindGroup:
		group, ok := value.(domain.Group)
		if !ok {
			return errors.New("interactive group payload is invalid")
		}
		if err := catalog.SaveGroup(ctx, &group); err != nil {
			return err
		}
		return printJSON(group)
	case domain.KindProfile:
		profile, ok := value.(domain.Profile)
		if !ok {
			return errors.New("interactive profile payload is invalid")
		}
		if err := catalog.SaveProfile(ctx, &profile); err != nil {
			return err
		}
		return printJSON(profile)
	case domain.KindIdentity:
		identity, ok := value.(domain.Identity)
		if !ok {
			return errors.New("interactive identity payload is invalid")
		}
		if err := catalog.SaveIdentity(ctx, &identity); err != nil {
			return err
		}
		return printJSON(identity)
	case domain.KindKey:
		key, ok := value.(domain.Key)
		if !ok {
			return errors.New("interactive key payload is invalid")
		}
		if err := catalog.SaveKey(ctx, &key); err != nil {
			return err
		}
		return printJSON(key)
	case domain.KindForward:
		forward, ok := value.(domain.Forward)
		if !ok {
			return errors.New("interactive forward payload is invalid")
		}
		if err := catalog.SaveForward(ctx, &forward); err != nil {
			return err
		}
		return printJSON(forward)
	default:
		return fmt.Errorf("unsupported kind %s", kind)
	}
}

func resolveSpecsToIDs(ctx context.Context, catalog *service.Catalog, kind domain.DocumentKind, specs []string) ([]string, error) {
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		id, err := catalog.ResolveDocumentID(ctx, kind, spec)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func parseKnownHostsPolicy(raw string) (domain.KnownHostsPolicy, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "strict":
		return domain.KnownHostsStrict, nil
	case "accept-new":
		return domain.KnownHostsAcceptNew, nil
	case "off":
		return domain.KnownHostsOff, nil
	default:
		return "", fmt.Errorf("invalid known hosts policy %q", raw)
	}
}

func parseKnownHostsBackend(raw string) (domain.KnownHostsBackend, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "vault":
		return domain.KnownHostsBackendVault, nil
	case "file":
		return domain.KnownHostsBackendFile, nil
	case "vault+file":
		return domain.KnownHostsBackendVaultFile, nil
	case "file+vault":
		return domain.KnownHostsBackendFileVault, nil
	default:
		return "", fmt.Errorf("invalid known hosts backend %q", raw)
	}
}

func buildKnownHostsConfig(policyRaw, backendRaw, pathRaw string) (*domain.KnownHostsConfig, error) {
	policyRaw = strings.TrimSpace(policyRaw)
	backendRaw = strings.TrimSpace(backendRaw)
	pathRaw = strings.TrimSpace(pathRaw)
	if policyRaw == "" && backendRaw == "" && pathRaw == "" {
		return nil, nil
	}
	cfg := &domain.KnownHostsConfig{}
	if policyRaw != "" {
		policy, err := parseKnownHostsPolicy(policyRaw)
		if err != nil {
			return nil, err
		}
		cfg.Policy = policy
	}
	if backendRaw != "" {
		backend, err := parseKnownHostsBackend(backendRaw)
		if err != nil {
			return nil, err
		}
		cfg.Backend = backend
	}
	if pathRaw != "" {
		cfg.Path = pathRaw
	}
	return cfg, nil
}

func stringPtr(value string) *string {
	return &value
}

func intPtr(value int) *int {
	return &value
}

func pluralizeKind(kind domain.DocumentKind) string {
	switch kind {
	case domain.KindIdentity:
		return "identities"
	default:
		return string(kind) + "s"
	}
}
