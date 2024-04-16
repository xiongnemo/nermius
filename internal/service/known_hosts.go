package service

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
)

type knownHostsSource string

const (
	knownHostsSourceVault knownHostsSource = "vault"
	knownHostsSourceFile  knownHostsSource = "file"
)

type knownHostsRuntimeConfig struct {
	Policy      domain.KnownHostsPolicy
	FilePath    string
	ReadSources []knownHostsSource
	WriteSource knownHostsSource
}

type parsedKnownHostLine struct {
	LineNumber int
	RawLine    string
	Entry      *domain.KnownHost
}

type knownHostsVerifier struct {
	cfg      knownHostsRuntimeConfig
	entries  []domain.KnownHost
	callback ssh.HostKeyCallback
	tempPath string
}

func (v *knownHostsVerifier) Close() error {
	if v == nil || v.tempPath == "" {
		return nil
	}
	return config.RemoveIfExists(v.tempPath)
}

func (v *knownHostsVerifier) PreferredAlgorithms(hostname string, remote net.Addr) []string {
	if v == nil {
		return defaultPreferredHostKeyAlgorithms()
	}
	matched := orderedKnownHostAlgorithms(v.entries, hostname, remote)
	if len(matched) == 0 {
		return defaultPreferredHostKeyAlgorithms()
	}
	return matched
}

func (v *knownHostsVerifier) Save(ctx context.Context, catalog *Catalog, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if v == nil {
		return nil
	}
	switch v.cfg.WriteSource {
	case knownHostsSourceFile:
		return appendKnownHost(v.cfg.FilePath, hostname, remote, key)
	default:
		entry := domain.KnownHost{
			Hosts:     knownHostAddresses(hostname, remote),
			Algorithm: key.Type(),
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
			Source:    string(domain.KnownHostsBackendVault),
		}
		return catalog.SaveKnownHost(ctx, &entry)
	}
}

func prepareKnownHostsVerifier(ctx context.Context, catalog *Catalog, resolved domain.ResolvedConfig, defaultPath string) (*knownHostsVerifier, error) {
	cfg := effectiveKnownHostsConfig(resolved, defaultPath)
	lines, entries, err := knownHostsLinesAndEntries(ctx, catalog, cfg)
	if err != nil {
		return nil, err
	}
	temp, err := os.CreateTemp("", "nermius-known-hosts-*.tmp")
	if err != nil {
		return nil, err
	}
	tempPath := temp.Name()
	if len(lines) > 0 {
		if _, err := io.WriteString(temp, strings.Join(lines, "\n")+"\n"); err != nil {
			_ = temp.Close()
			_ = os.Remove(tempPath)
			return nil, err
		}
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return nil, err
	}
	callback, err := knownhosts.New(tempPath)
	if err != nil {
		_ = os.Remove(tempPath)
		return nil, err
	}
	return &knownHostsVerifier{
		cfg:      cfg,
		entries:  entries,
		callback: callback,
		tempPath: tempPath,
	}, nil
}

func effectiveKnownHostsConfig(resolved domain.ResolvedConfig, defaultPath string) knownHostsRuntimeConfig {
	cfg := knownHostsRuntimeConfig{
		Policy:   domain.KnownHostsStrict,
		FilePath: defaultPath,
	}
	if resolved.KnownHosts.Policy != "" {
		cfg.Policy = resolved.KnownHosts.Policy
	}
	if resolved.KnownHosts.Path != "" {
		cfg.FilePath = config.ExpandUser(resolved.KnownHosts.Path)
	}
	switch resolved.KnownHosts.Backend {
	case domain.KnownHostsBackendVault:
		cfg.ReadSources = []knownHostsSource{knownHostsSourceVault}
		cfg.WriteSource = knownHostsSourceVault
	case domain.KnownHostsBackendFile:
		cfg.ReadSources = []knownHostsSource{knownHostsSourceFile}
		cfg.WriteSource = knownHostsSourceFile
	case domain.KnownHostsBackendFileVault:
		cfg.ReadSources = []knownHostsSource{knownHostsSourceFile, knownHostsSourceVault}
		cfg.WriteSource = knownHostsSourceFile
	default:
		cfg.ReadSources = []knownHostsSource{knownHostsSourceVault, knownHostsSourceFile}
		cfg.WriteSource = knownHostsSourceVault
	}
	return cfg
}

func knownHostsLinesAndEntries(ctx context.Context, catalog *Catalog, cfg knownHostsRuntimeConfig) ([]string, []domain.KnownHost, error) {
	lines := []string{}
	entries := []domain.KnownHost{}
	for _, source := range cfg.ReadSources {
		switch source {
		case knownHostsSourceVault:
			vaultEntries, err := catalog.ListKnownHosts(ctx)
			if err != nil {
				return nil, nil, err
			}
			for _, entry := range vaultEntries {
				line, err := formatKnownHostLine(entry)
				if err != nil {
					continue
				}
				lines = append(lines, line)
				entries = append(entries, entry)
			}
		case knownHostsSourceFile:
			parsed, err := parseKnownHostsFile(cfg.FilePath)
			if err != nil {
				return nil, nil, err
			}
			for _, line := range parsed {
				lines = append(lines, line.RawLine)
				if line.Entry != nil {
					entries = append(entries, *line.Entry)
				}
			}
		}
	}
	return lines, entries, nil
}

func ListKnownHostsEntries(ctx context.Context, catalog *Catalog, filePath, source string) ([]domain.KnownHost, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = "all"
	}
	out := []domain.KnownHost{}
	switch source {
	case "all", "vault":
		if source == "all" || source == "vault" {
			vaultEntries, err := catalog.ListKnownHosts(ctx)
			if err != nil {
				return nil, err
			}
			out = append(out, vaultEntries...)
		}
		if source != "all" {
			break
		}
		fallthrough
	case "file":
		if source == "all" || source == "file" {
			parsed, err := parseKnownHostsFile(filePath)
			if err != nil {
				return nil, err
			}
			for _, line := range parsed {
				if line.Entry != nil {
					out = append(out, *line.Entry)
				}
			}
		}
	default:
		if source != "all" && source != "vault" && source != "file" {
			return nil, errors.New("known host source must be one of: all, vault, file")
		}
	}
	return out, nil
}

func DeleteKnownHostsEntries(ctx context.Context, catalog *Catalog, filePath, spec, source string) (int, error) {
	source = strings.ToLower(strings.TrimSpace(source))
	if source == "" {
		source = "all"
	}
	deleted := 0
	if source == "all" || source == "vault" {
		entries, err := catalog.ListKnownHosts(ctx)
		if err != nil {
			return deleted, err
		}
		for _, entry := range entries {
			if !knownHostMatchesSpec(entry, spec) {
				continue
			}
			if err := catalog.Delete(ctx, entry.ID); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	if source == "all" || source == "file" {
		parsed, err := parseKnownHostsFile(filePath)
		if err != nil {
			return deleted, err
		}
		filtered := make([]string, 0, len(parsed))
		fileDeleted := 0
		for _, line := range parsed {
			if line.Entry != nil && knownHostMatchesSpec(*line.Entry, spec) {
				fileDeleted++
				continue
			}
			filtered = append(filtered, line.RawLine)
		}
		if fileDeleted > 0 {
			if err := ensureKnownHostsFile(filePath); err != nil {
				return deleted, err
			}
			body := ""
			if len(filtered) > 0 {
				body = strings.Join(filtered, "\n") + "\n"
			}
			if err := os.WriteFile(filePath, []byte(body), 0o600); err != nil {
				return deleted, err
			}
			deleted += fileDeleted
		}
	}
	if source != "all" && source != "vault" && source != "file" {
		return deleted, errors.New("known host source must be one of: all, vault, file")
	}
	return deleted, nil
}

func parseKnownHostsFile(path string) ([]parsedKnownHostLine, error) {
	path = config.ExpandUser(strings.TrimSpace(path))
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	lines := []parsedKnownHostLine{}
	scanner := bufio.NewScanner(file)
	for lineNumber := 1; scanner.Scan(); lineNumber++ {
		rawLine := strings.TrimSpace(scanner.Text())
		if rawLine == "" || strings.HasPrefix(rawLine, "#") {
			continue
		}
		lines = append(lines, parsedKnownHostLine{
			LineNumber: lineNumber,
			RawLine:    rawLine,
			Entry:      parseKnownHostLine(rawLine, lineNumber),
		})
	}
	return lines, scanner.Err()
}

func parseKnownHostLine(rawLine string, lineNumber int) *domain.KnownHost {
	fields := strings.Fields(rawLine)
	if len(fields) < 3 {
		return nil
	}
	offset := 0
	if strings.HasPrefix(fields[0], "@") {
		if len(fields) < 4 {
			return nil
		}
		offset = 1
	}
	hostsField := fields[offset]
	algorithm := fields[offset+1]
	publicKey := algorithm + " " + fields[offset+2]
	fingerprint, err := fingerprintAuthorizedKey(publicKey)
	if err != nil {
		return nil
	}
	return &domain.KnownHost{
		ID:                "file:" + strconv.Itoa(lineNumber),
		Hosts:             strings.Split(hostsField, ","),
		Algorithm:         algorithm,
		PublicKey:         publicKey,
		FingerprintSHA256: fingerprint,
		Source:            string(domain.KnownHostsBackendFile),
	}
}

func formatKnownHostLine(entry domain.KnownHost) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(entry.PublicKey)))
	if err != nil {
		return "", err
	}
	return knownhosts.Line(entry.Hosts, key), nil
}

func orderedKnownHostAlgorithms(entries []domain.KnownHost, hostname string, remote net.Addr) []string {
	saved := map[string]struct{}{}
	for _, entry := range entries {
		if !knownHostEntryMatchesHost(entry, hostname, remote) {
			continue
		}
		saved[entry.Algorithm] = struct{}{}
	}
	if len(saved) == 0 {
		return nil
	}
	ordered := []string{}
	defaults := defaultPreferredHostKeyAlgorithms()
	for _, algorithm := range defaults {
		if _, ok := saved[algorithm]; ok {
			ordered = append(ordered, algorithm)
			delete(saved, algorithm)
		}
	}
	extras := make([]string, 0, len(saved))
	for algorithm := range saved {
		extras = append(extras, algorithm)
	}
	slices.Sort(extras)
	ordered = append(ordered, extras...)
	for _, algorithm := range defaults {
		if slices.Contains(ordered, algorithm) {
			continue
		}
		ordered = append(ordered, algorithm)
	}
	return ordered
}

func defaultPreferredHostKeyAlgorithms() []string {
	algorithms := append([]string{}, ssh.SupportedAlgorithms().HostKeys...)
	for _, algorithm := range ssh.InsecureAlgorithms().HostKeys {
		if slices.Contains(algorithms, algorithm) {
			continue
		}
		algorithms = append(algorithms, algorithm)
	}
	return algorithms
}

func knownHostEntryMatchesHost(entry domain.KnownHost, hostname string, remote net.Addr) bool {
	candidates := knownHostMatchCandidates(hostname, remote)
	for _, host := range entry.Hosts {
		host = strings.TrimSpace(host)
		if host == "" || strings.HasPrefix(host, "|1|") {
			continue
		}
		for _, candidate := range candidates {
			if equalKnownHostToken(host, candidate) {
				return true
			}
		}
	}
	return false
}

func knownHostMatchesSpec(entry domain.KnownHost, spec string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return false
	}
	if entry.ID == spec {
		return true
	}
	if strings.EqualFold(entry.FingerprintSHA256, spec) {
		return true
	}
	for _, host := range entry.Hosts {
		if equalKnownHostToken(host, spec) {
			return true
		}
	}
	return false
}

func knownHostMatchCandidates(hostname string, remote net.Addr) []string {
	out := []string{}
	appendUnique := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range out {
			if equalKnownHostToken(existing, value) {
				return
			}
		}
		out = append(out, value)
	}
	appendUnique(hostname)
	appendUnique(knownhosts.Normalize(hostname))
	if host, port, err := net.SplitHostPort(hostname); err == nil {
		appendUnique(host)
		appendUnique(knownhosts.Normalize(host))
		appendUnique("[" + host + "]:" + port)
		if port == "22" {
			appendUnique(host)
		}
	}
	if remote != nil {
		appendUnique(remote.String())
		if tcp, ok := remote.(*net.TCPAddr); ok {
			appendUnique(tcp.IP.String())
			appendUnique(net.JoinHostPort(tcp.IP.String(), strconv.Itoa(tcp.Port)))
			if tcp.Port == 22 {
				appendUnique(tcp.IP.String())
			}
		}
	}
	return out
}

func equalKnownHostToken(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return false
	}
	if left == right {
		return true
	}
	normalizedLeft := normalizeKnownHostToken(left)
	normalizedRight := normalizeKnownHostToken(right)
	return normalizedLeft == normalizedRight
}

func normalizeKnownHostToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	out := []string{value}
	if normalized := knownhosts.Normalize(value); normalized != "" {
		out = append(out, normalized)
	}
	if host, port, err := net.SplitHostPort(value); err == nil {
		out = append(out, host, "["+host+"]:"+port)
		if port == "22" {
			out = append(out, host)
		}
	}
	if strings.HasPrefix(value, "[") && strings.Contains(value, "]:") {
		end := strings.Index(value, "]:")
		host := value[1:end]
		port := value[end+2:]
		out = append(out, host)
		if port == "22" {
			out = append(out, host)
		}
	}
	slices.Sort(out)
	return strings.Join(slices.Compact(out), "|")
}

func knownHostsTempPath(dir string) string {
	return filepath.Join(dir, "known_hosts")
}
