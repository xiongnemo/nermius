package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kevinburke/ssh_config"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
)

type ImportReport struct {
	Hosts      int `json:"hosts"`
	Identities int `json:"identities"`
	Keys       int `json:"keys"`
	Forwards   int `json:"forwards"`
}

type OpenSSHImporter struct {
	catalog *Catalog
}

func NewOpenSSHImporter(catalog *Catalog) *OpenSSHImporter {
	return &OpenSSHImporter{catalog: catalog}
}

func (i *OpenSSHImporter) Import(ctx context.Context, configPath string) (ImportReport, error) {
	path := config.ExpandUser(configPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		return ImportReport{}, err
	}
	cfg, err := ssh_config.Decode(strings.NewReader(string(raw)))
	if err != nil {
		return ImportReport{}, err
	}
	report := ImportReport{}
	for _, block := range cfg.Hosts {
		for _, pattern := range block.Patterns {
			alias := strings.TrimSpace(fmt.Sprint(pattern))
			if alias == "" || strings.ContainsAny(alias, "*?!") {
				continue
			}
			hostReport, err := i.importAlias(ctx, cfg, alias, filepath.Dir(path))
			if err != nil {
				return report, fmt.Errorf("import %s: %w", alias, err)
			}
			report.Hosts += hostReport.Hosts
			report.Identities += hostReport.Identities
			report.Keys += hostReport.Keys
			report.Forwards += hostReport.Forwards
			break
		}
	}
	return report, nil
}

func (i *OpenSSHImporter) importAlias(ctx context.Context, cfg *ssh_config.Config, alias, baseDir string) (ImportReport, error) {
	var report ImportReport
	hostname, _ := cfg.Get(alias, "Hostname")
	if hostname == "" {
		hostname = alias
	}
	host := domain.Host{
		Title:    alias,
		Hostname: hostname,
	}
	if rawPort, _ := cfg.Get(alias, "Port"); rawPort != "" {
		if port, err := strconv.Atoi(rawPort); err == nil {
			host.Port = intPtr(port)
		}
	}
	if jump, _ := cfg.Get(alias, "ProxyJump"); jump != "" {
		host.Route = &domain.Route{
			ProxyJump: splitCSV(jump),
		}
	}
	if rawStrict, _ := cfg.Get(alias, "StrictHostKeyChecking"); rawStrict != "" {
		host.KnownHosts = &domain.KnownHostsConfig{Policy: strictHostKeyPolicy(rawStrict)}
	}
	if forwards, count, err := i.importForwards(ctx, alias, cfg); err != nil {
		return report, err
	} else {
		host.ForwardIDs = forwards
		report.Forwards += count
	}
	if identityID, keyCount, err := i.importIdentity(ctx, alias, cfg, baseDir); err != nil {
		return report, err
	} else {
		report.Keys += keyCount
		if identityID != "" {
			report.Identities++
			host.IdentityRef = &identityID
		}
	}
	if err := i.catalog.SaveHost(ctx, &host); err != nil {
		return report, err
	}
	report.Hosts++
	return report, nil
}

func (i *OpenSSHImporter) importIdentity(ctx context.Context, alias string, cfg *ssh_config.Config, baseDir string) (string, int, error) {
	username, _ := cfg.Get(alias, "User")
	identityFiles, _ := cfg.GetAll(alias, "IdentityFile")
	if username == "" && len(identityFiles) == 0 {
		return "", 0, nil
	}
	identity := domain.Identity{
		Name:     "import:" + alias,
		Username: username,
		Methods:  []domain.AuthMethod{},
	}
	keyCount := 0
	for _, file := range identityFiles {
		key := domain.Key{
			Name:       "import:" + alias + ":" + filepath.Base(file),
			Kind:       domain.KeyKindPrivateKey,
			SourcePath: resolveImportPath(file, baseDir),
		}
		if err := i.catalog.SaveKey(ctx, &key); err != nil {
			return "", keyCount, err
		}
		identity.Methods = append(identity.Methods, domain.AuthMethod{
			Type:  domain.AuthMethodKey,
			KeyID: key.ID,
		})
		keyCount++
	}
	if len(identity.Methods) == 0 {
		identity.Methods = append(identity.Methods, domain.AuthMethod{Type: domain.AuthMethodAgent})
	}
	if identity.Username == "" {
		identity.Username = os.Getenv("USER")
		if identity.Username == "" {
			identity.Username = os.Getenv("USERNAME")
		}
	}
	if err := i.catalog.SaveIdentity(ctx, &identity); err != nil {
		return "", keyCount, err
	}
	return identity.ID, keyCount, nil
}

func (i *OpenSSHImporter) importForwards(ctx context.Context, alias string, cfg *ssh_config.Config) ([]string, int, error) {
	ids := []string{}
	count := 0
	localForwards, _ := cfg.GetAll(alias, "LocalForward")
	for _, raw := range localForwards {
		forward, err := parseForwardSpec("import:"+alias+":local", domain.ForwardLocal, raw)
		if err != nil {
			return nil, count, err
		}
		if err := i.catalog.SaveForward(ctx, &forward); err != nil {
			return nil, count, err
		}
		ids = append(ids, forward.ID)
		count++
	}
	remoteForwards, _ := cfg.GetAll(alias, "RemoteForward")
	for _, raw := range remoteForwards {
		forward, err := parseForwardSpec("import:"+alias+":remote", domain.ForwardRemote, raw)
		if err != nil {
			return nil, count, err
		}
		if err := i.catalog.SaveForward(ctx, &forward); err != nil {
			return nil, count, err
		}
		ids = append(ids, forward.ID)
		count++
	}
	dynamicForwards, _ := cfg.GetAll(alias, "DynamicForward")
	for _, raw := range dynamicForwards {
		forward, err := parseForwardSpec("import:"+alias+":dynamic", domain.ForwardDynamic, raw)
		if err != nil {
			return nil, count, err
		}
		if err := i.catalog.SaveForward(ctx, &forward); err != nil {
			return nil, count, err
		}
		ids = append(ids, forward.ID)
		count++
	}
	return ids, count, nil
}

func strictHostKeyPolicy(raw string) domain.KnownHostsPolicy {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "no", "off":
		return domain.KnownHostsOff
	case "accept-new":
		return domain.KnownHostsAcceptNew
	default:
		return domain.KnownHostsStrict
	}
}

func resolveImportPath(path, baseDir string) string {
	path = config.ExpandUser(path)
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(baseDir, path)
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func parseForwardSpec(prefix string, forwardType domain.ForwardType, raw string) (domain.Forward, error) {
	fields := strings.Fields(raw)
	switch forwardType {
	case domain.ForwardDynamic:
		addr, err := parseListenAddr(firstOrEmpty(fields))
		if err != nil {
			return domain.Forward{}, err
		}
		return domain.Forward{
			Name:       prefix + ":" + addr,
			Type:       domain.ForwardDynamic,
			ListenHost: hostPart(addr),
			ListenPort: portPart(addr),
			Enabled:    true,
			AutoStart:  true,
		}, nil
	case domain.ForwardLocal, domain.ForwardRemote:
		if len(fields) != 2 {
			return domain.Forward{}, fmt.Errorf("invalid forward spec %q", raw)
		}
		listenAddr, err := parseListenAddr(fields[0])
		if err != nil {
			return domain.Forward{}, err
		}
		targetAddr, err := parseTargetAddr(fields[1])
		if err != nil {
			return domain.Forward{}, err
		}
		return domain.Forward{
			Name:       prefix + ":" + listenAddr + "->" + targetAddr,
			Type:       forwardType,
			ListenHost: hostPart(listenAddr),
			ListenPort: portPart(listenAddr),
			TargetHost: hostPart(targetAddr),
			TargetPort: portPart(targetAddr),
			Enabled:    true,
			AutoStart:  true,
		}, nil
	default:
		return domain.Forward{}, fmt.Errorf("unsupported forward type %s", forwardType)
	}
}

func parseListenAddr(raw string) (string, error) {
	if !strings.Contains(raw, ":") {
		raw = "127.0.0.1:" + raw
	}
	_, _, err := splitHostPort(raw)
	return raw, err
}

func parseTargetAddr(raw string) (string, error) {
	_, _, err := splitHostPort(raw)
	return raw, err
}

func hostPart(addr string) string {
	host, _, _ := splitHostPort(addr)
	return host
}

func portPart(addr string) int {
	_, port, _ := splitHostPort(addr)
	return port
}

func splitHostPort(raw string) (string, int, error) {
	idx := strings.LastIndex(raw, ":")
	if idx <= 0 || idx == len(raw)-1 {
		return "", 0, fmt.Errorf("invalid address %q", raw)
	}
	port, err := strconv.Atoi(raw[idx+1:])
	if err != nil {
		return "", 0, err
	}
	return raw[:idx], port, nil
}

func firstOrEmpty(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func intPtr(v int) *int { return &v }
