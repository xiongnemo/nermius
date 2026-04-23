package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/service"
)

type interactiveMode struct {
	interactive bool
	tty         bool
}

func (m interactiveMode) Enabled() bool {
	return m.interactive || m.tty
}

func bindInteractiveFlags(cmd *cobra.Command, mode *interactiveMode) {
	cmd.Flags().BoolVarP(&mode.interactive, "interactive", "i", false, "Prompt interactively (`-it` works too)")
	cmd.Flags().BoolVarP(&mode.tty, "tty", "t", false, "Compatibility flag so `-it` works")
	_ = cmd.Flags().MarkHidden("tty")
}

func promptLine(label, defaultValue string, required bool) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		if defaultValue != "" {
			fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultValue)
		} else {
			fmt.Fprintf(os.Stderr, "%s: ", label)
		}
		value, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(value)
		if value == "" {
			value = defaultValue
		}
		if value == "" && required {
			fmt.Fprintln(os.Stderr, "This value is required.")
			continue
		}
		return value, nil
	}
}

func promptOptionalInt(label string, defaultValue *int) (*int, error) {
	defaultText := ""
	if defaultValue != nil {
		defaultText = strconv.Itoa(*defaultValue)
	}
	value, err := promptLine(label, defaultText, false)
	if err != nil {
		return nil, err
	}
	if value == "" {
		return nil, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return nil, err
	}
	return &number, nil
}

func promptBool(label string, defaultValue bool) (bool, error) {
	defaultText := "y/N"
	if defaultValue {
		defaultText = "Y/n"
	}
	for {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultText)
		reader := bufio.NewReader(os.Stdin)
		value, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "":
			return defaultValue, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(os.Stderr, "Please enter y or n.")
		}
	}
}

func promptChoice(label string, options []string, defaultValue string, allowBlank bool) (string, error) {
	optionSet := map[string]struct{}{}
	for _, option := range options {
		optionSet[strings.ToLower(option)] = struct{}{}
	}
	for {
		value, err := promptLine(label, defaultValue, false)
		if err != nil {
			return "", err
		}
		if value == "" && allowBlank {
			return "", nil
		}
		if _, ok := optionSet[strings.ToLower(value)]; ok {
			return strings.ToLower(value), nil
		}
		fmt.Fprintf(os.Stderr, "Choose one of: %s\n", strings.Join(options, ", "))
	}
}

func promptCSV(label string, defaults []string) ([]string, error) {
	defaultText := strings.Join(defaults, ",")
	value, err := promptLine(label, defaultText, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out, nil
}

func promptSecretInteractive(label string, required bool) (string, error) {
	return promptSecretInteractiveWithDefault(label, "", required)
}

func promptSecretInteractiveWithDefault(label, defaultValue string, required bool) (string, error) {
	for {
		fmt.Fprintf(os.Stderr, "%s: ", label)
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		trimmed := strings.TrimSpace(string(value))
		if trimmed == "" && defaultValue != "" {
			return defaultValue, nil
		}
		if trimmed == "" && required {
			fmt.Fprintln(os.Stderr, "This value is required.")
			continue
		}
		return trimmed, nil
	}
}

func promptRoute(defaultRoute *domain.Route) (*domain.Route, error) {
	defaultJumps := []string{}
	if defaultRoute != nil {
		defaultJumps = defaultRoute.ProxyJump
	}
	jumps, err := promptCSV("Jump hosts (comma-separated name/ID or user@host:port, blank for none)", defaultJumps)
	if err != nil {
		return nil, err
	}
	defaultProxyType := ""
	if defaultRoute != nil && defaultRoute.OutboundProxy != nil {
		defaultProxyType = string(defaultRoute.OutboundProxy.Type)
	}
	proxyType, err := promptChoice("Outbound proxy type (blank, socks5, http)", []string{"socks5", "http"}, defaultProxyType, true)
	if err != nil {
		return nil, err
	}
	if len(jumps) == 0 && proxyType == "" {
		return nil, nil
	}
	route := &domain.Route{
		ProxyJump: jumps,
	}
	if proxyType == "" {
		return route, nil
	}
	var defaultAddress, defaultUsername string
	if defaultRoute != nil && defaultRoute.OutboundProxy != nil {
		defaultAddress = defaultRoute.OutboundProxy.Address
		defaultUsername = defaultRoute.OutboundProxy.Username
	}
	address, err := promptLine("Proxy address", defaultAddress, true)
	if err != nil {
		return nil, err
	}
	username, err := promptLine("Proxy username", defaultUsername, false)
	if err != nil {
		return nil, err
	}
	password, err := promptSecretInteractive("Proxy password (blank for none)", false)
	if err != nil {
		return nil, err
	}
	route.OutboundProxy = &domain.OutboundProxy{
		Type:     domain.ProxyType(proxyType),
		Address:  address,
		Username: username,
		Password: password,
	}
	return route, nil
}

func promptKnownHostsConfig(defaultValue *domain.KnownHostsConfig) (*domain.KnownHostsConfig, error) {
	defaultPolicy := ""
	defaultBackend := ""
	defaultPath := ""
	if defaultValue != nil {
		defaultPolicy = string(defaultValue.Policy)
		if defaultValue.Backend != "" {
			defaultBackend = string(defaultValue.Backend)
		}
		defaultPath = defaultValue.Path
	}
	policy, err := promptChoice("Known hosts policy (blank, strict, accept-new, off)", []string{"strict", "accept-new", "off"}, defaultPolicy, true)
	if err != nil {
		return nil, err
	}
	backend, err := promptChoice("Known hosts backend (blank, vault, file, vault+file, file+vault)", []string{"vault", "file", "vault+file", "file+vault"}, defaultBackend, true)
	if err != nil {
		return nil, err
	}
	path, err := promptLine("Known hosts file path override (blank for default)", defaultPath, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(policy) == "" && strings.TrimSpace(backend) == "" && strings.TrimSpace(path) == "" {
		return nil, nil
	}
	cfg := &domain.KnownHostsConfig{}
	if strings.TrimSpace(policy) != "" {
		cfg.Policy = domain.KnownHostsPolicy(policy)
	}
	if strings.TrimSpace(backend) != "" {
		cfg.Backend = domain.KnownHostsBackend(backend)
	}
	if strings.TrimSpace(path) != "" {
		cfg.Path = path
	}
	return cfg, nil
}

func promptHostInteractive(ctx context.Context, catalog *service.Catalog, defaults domain.Host) (domain.Host, error) {
	var out domain.Host
	var err error
	out.ID = defaults.ID
	out.Title, err = promptLine("Title", defaults.Title, false)
	if err != nil {
		return out, err
	}
	out.Hostname, err = promptLine("Hostname", defaults.Hostname, true)
	if err != nil {
		return out, err
	}
	out.Port, err = promptOptionalInt("Port", defaults.Port)
	if err != nil {
		return out, err
	}
	usernameDefault := derefString(defaults.Username)
	username, err := promptLine("Username override", usernameDefault, false)
	if err != nil {
		return out, err
	}
	if username != "" {
		out.Username = stringPtr(username)
	}
	groupSpecs, err := promptCSV("Groups (comma-separated names/IDs)", defaults.GroupIDs)
	if err != nil {
		return out, err
	}
	if out.GroupIDs, err = resolveSpecsToIDs(ctx, catalog, domain.KindGroup, groupSpecs); err != nil {
		return out, err
	}
	profileSpecs, err := promptCSV("Profiles in order (comma-separated names/IDs)", defaults.ProfileIDs)
	if err != nil {
		return out, err
	}
	if out.ProfileIDs, err = resolveSpecsToIDs(ctx, catalog, domain.KindProfile, profileSpecs); err != nil {
		return out, err
	}
	identityDefault := derefString(defaults.IdentityRef)
	identitySpec, err := promptLine("Identity", identityDefault, false)
	if err != nil {
		return out, err
	}
	if identitySpec != "" {
		id, err := catalog.ResolveDocumentID(ctx, domain.KindIdentity, identitySpec)
		if err != nil {
			return out, err
		}
		out.IdentityRef = &id
	}
	keyDefault := derefString(defaults.KeyRef)
	keySpec, err := promptLine("Direct key override (name/ID, overrides identity/profile auth)", keyDefault, false)
	if err != nil {
		return out, err
	}
	if keySpec != "" {
		id, err := catalog.ResolveDocumentID(ctx, domain.KindKey, keySpec)
		if err != nil {
			return out, err
		}
		out.KeyRef = &id
	}
	password, err := promptSecretInteractiveWithDefault("Direct password override (blank to inherit identity/profile auth)", defaults.Password, false)
	if err != nil {
		return out, err
	}
	if password != "" {
		out.Password = password
	}
	forwardSpecs, err := promptCSV("Forwards (comma-separated names/IDs)", defaults.ForwardIDs)
	if err != nil {
		return out, err
	}
	if out.ForwardIDs, err = resolveSpecsToIDs(ctx, catalog, domain.KindForward, forwardSpecs); err != nil {
		return out, err
	}
	out.KnownHosts, err = promptKnownHostsConfig(defaults.KnownHosts)
	if err != nil {
		return out, err
	}
	out.Route, err = promptRoute(defaults.Route)
	if err != nil {
		return out, err
	}
	return out, nil
}

func promptGroupInteractive(defaults domain.Group) (domain.Group, error) {
	var out domain.Group
	var err error
	out.ID = defaults.ID
	out.Name, err = promptLine("Name", defaults.Name, true)
	if err != nil {
		return out, err
	}
	out.Description, err = promptLine("Description", defaults.Description, false)
	return out, err
}

func promptProfileInteractive(ctx context.Context, catalog *service.Catalog, defaults domain.Profile) (domain.Profile, error) {
	var out domain.Profile
	var err error
	out.ID = defaults.ID
	out.Name, err = promptLine("Name", defaults.Name, true)
	if err != nil {
		return out, err
	}
	out.Description, err = promptLine("Description", defaults.Description, false)
	if err != nil {
		return out, err
	}
	out.Port, err = promptOptionalInt("Port", defaults.Port)
	if err != nil {
		return out, err
	}
	username, err := promptLine("Username default", derefString(defaults.Username), false)
	if err != nil {
		return out, err
	}
	if username != "" {
		out.Username = stringPtr(username)
	}
	identitySpec, err := promptLine("Identity", derefString(defaults.IdentityRef), false)
	if err != nil {
		return out, err
	}
	if identitySpec != "" {
		id, err := catalog.ResolveDocumentID(ctx, domain.KindIdentity, identitySpec)
		if err != nil {
			return out, err
		}
		out.IdentityRef = &id
	}
	forwardSpecs, err := promptCSV("Forwards (comma-separated names/IDs)", defaults.ForwardIDs)
	if err != nil {
		return out, err
	}
	if out.ForwardIDs, err = resolveSpecsToIDs(ctx, catalog, domain.KindForward, forwardSpecs); err != nil {
		return out, err
	}
	out.KnownHosts, err = promptKnownHostsConfig(defaults.KnownHosts)
	if err != nil {
		return out, err
	}
	out.Route, err = promptRoute(defaults.Route)
	return out, err
}

func promptIdentityInteractive(ctx context.Context, catalog *service.Catalog, defaults domain.Identity) (domain.Identity, error) {
	var out domain.Identity
	var err error
	out.ID = defaults.ID
	out.Name, err = promptLine("Name", defaults.Name, true)
	if err != nil {
		return out, err
	}
	out.Username, err = promptLine("Username", defaults.Username, true)
	if err != nil {
		return out, err
	}
	methods := make([]domain.AuthMethod, 0, max(1, len(defaults.Methods)))
	for {
		defaultChoice := ""
		if len(defaults.Methods) > len(methods) {
			defaultChoice = string(defaults.Methods[len(methods)].Type)
		}
		choice, err := promptChoice("Auth method (password, key, agent; blank to finish)", []string{"password", "key", "agent"}, defaultChoice, len(methods) > 0)
		if err != nil {
			return out, err
		}
		if choice == "" {
			break
		}
		method := domain.AuthMethod{Type: domain.AuthMethodType(choice)}
		switch method.Type {
		case domain.AuthMethodPassword:
			password, err := promptSecretInteractive("Password", true)
			if err != nil {
				return out, err
			}
			method.Password = password
		case domain.AuthMethodKey:
			keySpec, err := promptLine("Key name or ID", "", true)
			if err != nil {
				return out, err
			}
			keyID, err := catalog.ResolveDocumentID(ctx, domain.KindKey, keySpec)
			if err != nil {
				return out, err
			}
			method.KeyID = keyID
		case domain.AuthMethodAgent:
			socket, err := promptLine("Agent socket (blank for default SSH_AUTH_SOCK)", "", false)
			if err != nil {
				return out, err
			}
			method.AgentSocket = socket
			method.AgentForward, err = promptBool("Enable agent forwarding", false)
			if err != nil {
				return out, err
			}
		}
		methods = append(methods, method)
	}
	if len(methods) == 0 {
		return out, errors.New("at least one auth method is required")
	}
	out.Methods = methods
	return out, nil
}

func promptKeyInteractive(defaults domain.Key) (domain.Key, error) {
	var out domain.Key
	var err error
	out.ID = defaults.ID
	out.Name, err = promptLine("Name", defaults.Name, true)
	if err != nil {
		return out, err
	}
	defaultKind := string(defaults.Kind)
	if defaultKind == "" {
		defaultKind = string(domain.KeyKindPrivateKey)
	}
	kind, err := promptChoice("Key kind (private_key, agent)", []string{"private_key", "agent"}, defaultKind, false)
	if err != nil {
		return out, err
	}
	out.Kind = domain.KeyKind(kind)
	switch out.Kind {
	case domain.KeyKindAgent:
		out.AgentSocket, err = promptLine("Agent socket (blank for default SSH_AUTH_SOCK)", defaults.AgentSocket, false)
		return out, err
	case domain.KeyKindPrivateKey:
		path, err := promptLine("Private key file path", defaults.SourcePath, true)
		if err != nil {
			return out, err
		}
		importIntoVault, err := promptBool("Import key contents into vault", true)
		if err != nil {
			return out, err
		}
		expanded := config.ExpandUser(path)
		if importIntoVault {
			raw, err := os.ReadFile(expanded)
			if err != nil {
				return out, err
			}
			out.PrivateKeyPEM = string(raw)
		} else {
			out.SourcePath = expanded
		}
		out.Passphrase, err = promptSecretInteractive("Key passphrase (blank for none)", false)
		return out, err
	default:
		return out, fmt.Errorf("unsupported key kind %q", out.Kind)
	}
}

func promptForwardInteractive(defaults domain.Forward) (domain.Forward, error) {
	var out domain.Forward
	var err error
	out.ID = defaults.ID
	out.Name, err = promptLine("Name", defaults.Name, true)
	if err != nil {
		return out, err
	}
	out.Description, err = promptLine("Description", defaults.Description, false)
	if err != nil {
		return out, err
	}
	defaultType := string(defaults.Type)
	if defaultType == "" {
		defaultType = string(domain.ForwardLocal)
	}
	forwardType, err := promptChoice("Forward type (local, remote, dynamic)", []string{"local", "remote", "dynamic"}, defaultType, false)
	if err != nil {
		return out, err
	}
	out.Type = domain.ForwardType(forwardType)
	defaultListenHost := defaults.ListenHost
	if defaultListenHost == "" {
		defaultListenHost = "127.0.0.1"
	}
	out.ListenHost, err = promptLine("Listen host", defaultListenHost, false)
	if err != nil {
		return out, err
	}
	var defaultListenPort *int
	if defaults.ListenPort > 0 {
		defaultListenPort = intPtr(defaults.ListenPort)
	}
	listenPort, err := promptOptionalInt("Listen port", defaultListenPort)
	if err != nil {
		return out, err
	}
	if listenPort == nil {
		return out, errors.New("listen port is required")
	}
	out.ListenPort = *listenPort
	if out.Type != domain.ForwardDynamic {
		out.TargetHost, err = promptLine("Target host", defaults.TargetHost, true)
		if err != nil {
			return out, err
		}
		var defaultTargetPort *int
		if defaults.TargetPort > 0 {
			defaultTargetPort = intPtr(defaults.TargetPort)
		}
		targetPort, err := promptOptionalInt("Target port", defaultTargetPort)
		if err != nil {
			return out, err
		}
		if targetPort == nil {
			return out, errors.New("target port is required")
		}
		out.TargetPort = *targetPort
	}
	out.AutoStart, err = promptBool("Auto start this forward", defaults.AutoStart)
	if err != nil {
		return out, err
	}
	enabledDefault := defaults.Enabled
	if !defaults.Enabled && defaults.ID == "" {
		enabledDefault = true
	}
	out.Enabled, err = promptBool("Enable this forward", enabledDefault)
	return out, err
}

func buildInteractiveDocument(ctx context.Context, catalog *service.Catalog, kind domain.DocumentKind) (any, error) {
	switch kind {
	case domain.KindHost:
		return promptHostInteractive(ctx, catalog, domain.Host{})
	case domain.KindGroup:
		return promptGroupInteractive(domain.Group{})
	case domain.KindProfile:
		return promptProfileInteractive(ctx, catalog, domain.Profile{})
	case domain.KindIdentity:
		return promptIdentityInteractive(ctx, catalog, domain.Identity{})
	case domain.KindKey:
		return promptKeyInteractive(domain.Key{})
	case domain.KindForward:
		return promptForwardInteractive(domain.Forward{})
	default:
		return nil, fmt.Errorf("interactive mode is not supported for %s", kind)
	}
}

func derefString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
