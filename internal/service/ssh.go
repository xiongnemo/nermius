package service

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/term"

	"github.com/nermius/nermius/internal/config"
	"github.com/nermius/nermius/internal/domain"
	"github.com/nermius/nermius/internal/termemu"
)

type Prompts struct {
	Text    func(label string) (string, error)
	Secret  func(label string) (string, error)
	Confirm func(label string) (bool, error)
}

type CommandExitError struct {
	Code int
}

func (e *CommandExitError) Error() string {
	return ""
}

func (e *CommandExitError) ExitCode() int {
	if e == nil || e.Code <= 0 {
		return 1
	}
	return e.Code
}

type Connector struct {
	Catalog           *Catalog
	DefaultKnownHosts string
	Verbosity         int
}

type EmbeddedSession struct {
	Name     string
	Resolved domain.ResolvedConfig
	Terminal termemu.Terminal

	client   *ssh.Client
	session  *ssh.Session
	stdin    io.WriteCloser
	closers  []io.Closer
	waitOnce sync.Once
	done     chan error
}

func NewConnector(catalog *Catalog, knownHostsPath string) *Connector {
	return &Connector{Catalog: catalog, DefaultKnownHosts: knownHostsPath}
}

func (c *Connector) ConnectInteractive(ctx context.Context, spec string, prompts Prompts, extraForwards []domain.Forward) error {
	resolved, client, cleanups, err := c.openClient(ctx, spec, prompts)
	if err != nil {
		return err
	}
	defer closeAll(cleanups)
	defer client.Close()

	forwards := append([]domain.Forward{}, resolved.Forwards...)
	forwards = append(forwards, extraForwards...)
	listenerClosers, err := c.startForwards(ctx, client, forwards)
	if err != nil {
		return err
	}
	defer closeAll(listenerClosers)

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	width, height := consoleTerminalSize()
	oldState, err := term.MakeRaw(fd)
	if err == nil {
		defer func() { _ = term.Restore(fd, oldState) }()
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", height, width, modes); err != nil {
		return err
	}
	session.Stdout = os.Stdout
	session.Stderr = os.Stderr
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(stdin, os.Stdin)
	}()
	resizeCtx, cancelResize := context.WithCancel(ctx)
	defer cancelResize()
	go c.watchConsoleResize(resizeCtx, 250*time.Millisecond, func(cols, rows int) {
		_ = session.WindowChange(rows, cols)
	})
	if err := session.Shell(); err != nil {
		return err
	}
	return session.Wait()
}

func (c *Connector) Exec(ctx context.Context, spec, command string, prompts Prompts, extraForwards []domain.Forward, stdin io.Reader, stdout, stderr io.Writer) error {
	if strings.TrimSpace(command) == "" {
		return errors.New("remote command is required")
	}
	resolved, client, cleanups, err := c.openClient(ctx, spec, prompts)
	if err != nil {
		return err
	}
	defer closeAll(cleanups)
	defer client.Close()

	forwards := append([]domain.Forward{}, resolved.Forwards...)
	forwards = append(forwards, extraForwards...)
	listenerClosers, err := c.startForwards(ctx, client, forwards)
	if err != nil {
		return err
	}
	defer closeAll(listenerClosers)

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdin = stdin
	session.Stdout = stdout
	session.Stderr = stderr
	if err := session.Run(command); err != nil {
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			return &CommandExitError{Code: exitErr.ExitStatus()}
		}
		return err
	}
	return nil
}

func (c *Connector) OpenEmbeddedSession(ctx context.Context, spec string, prompts Prompts, cols, rows int) (*EmbeddedSession, error) {
	resolved, client, cleanups, err := c.openClient(ctx, spec, prompts)
	if err != nil {
		return nil, err
	}
	listenerClosers, err := c.startForwards(ctx, client, resolved.Forwards)
	if err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	cleanups = append(cleanups, listenerClosers...)
	session, err := client.NewSession()
	if err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	if cols <= 0 {
		cols = 120
	}
	if rows <= 0 {
		rows = 32
	}
	termView := termemu.New(cols, rows)
	stdout, err := session.StdoutPipe()
	if err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	if err := session.RequestPty("xterm-256color", rows, cols, ssh.TerminalModes{ssh.ECHO: 1}); err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	if err := session.Shell(); err != nil {
		closeAll(cleanups)
		client.Close()
		return nil, err
	}
	embedded := &EmbeddedSession{
		Name:     resolved.Label,
		Resolved: resolved,
		Terminal: termView,
		client:   client,
		session:  session,
		stdin:    stdin,
		closers:  cleanups,
		done:     make(chan error, 1),
	}
	go func() { _, _ = io.Copy(termView, stdout) }()
	go func() { _, _ = io.Copy(termView, stderr) }()
	go func() {
		embedded.done <- session.Wait()
	}()
	return embedded, nil
}

func (s *EmbeddedSession) WriteKeys(data []byte) error {
	_, err := s.stdin.Write(data)
	return err
}

func (s *EmbeddedSession) Resize(cols, rows int) error {
	s.Terminal.Resize(cols, rows)
	return s.session.WindowChange(rows, cols)
}

func (s *EmbeddedSession) SetClipboardHandler(handler func(string)) {
	s.Terminal.SetClipboardHandler(handler)
}

func (s *EmbeddedSession) Paste(text string) error {
	if text == "" {
		return nil
	}
	payload := []byte(text)
	s.Terminal.Lock()
	mode := s.Terminal.Mode()
	s.Terminal.Unlock()
	if mode&termemu.ModeBracketedPaste != 0 {
		payload = append([]byte("\x1b[200~"), payload...)
		payload = append(payload, []byte("\x1b[201~")...)
	}
	return s.WriteKeys(payload)
}

func (s *EmbeddedSession) SendFocus(focused bool) error {
	s.Terminal.Lock()
	mode := s.Terminal.Mode()
	s.Terminal.Unlock()
	if mode&termemu.ModeFocus == 0 {
		return nil
	}
	seq := "\x1b[O"
	if focused {
		seq = "\x1b[I"
	}
	return s.WriteKeys([]byte(seq))
}

func (s *EmbeddedSession) Done() <-chan error {
	return s.done
}

func (s *EmbeddedSession) Close() error {
	var err error
	s.waitOnce.Do(func() {
		_ = s.session.Close()
		_ = s.client.Close()
		err = closeAll(s.closers)
	})
	return err
}

func (c *Connector) openClient(ctx context.Context, spec string, prompts Prompts) (domain.ResolvedConfig, *ssh.Client, []io.Closer, error) {
	resolved, err := c.Catalog.ResolveHost(ctx, spec)
	if err != nil {
		return domain.ResolvedConfig{}, nil, nil, err
	}
	prepared, err := c.prepareResolved(ctx, resolved, prompts)
	if err != nil {
		return domain.ResolvedConfig{}, nil, nil, err
	}
	client, closers, err := c.dialResolved(ctx, prepared, prompts)
	if err != nil {
		return domain.ResolvedConfig{}, nil, nil, err
	}
	return prepared, client, closers, nil
}

func (c *Connector) prepareResolved(ctx context.Context, resolved domain.ResolvedConfig, prompts Prompts) (domain.ResolvedConfig, error) {
	if resolved.Username == "" && prompts.Text != nil {
		value, err := prompts.Text("Username")
		if err != nil {
			return resolved, err
		}
		resolved.Username = value
	}
	if resolved.Identity != nil && resolved.Identity.Username == "" {
		resolved.Identity.Username = resolved.Username
	}
	if len(resolved.AuthMethods) == 0 {
		resolved.AuthMethods = []domain.AuthMethod{{Type: domain.AuthMethodPassword}}
	}
	return resolved, nil
}

func (c *Connector) dialResolved(ctx context.Context, resolved domain.ResolvedConfig, prompts Prompts) (*ssh.Client, []io.Closer, error) {
	chain, err := c.buildJumpChain(ctx, resolved, prompts)
	if err != nil {
		return nil, nil, err
	}
	var closers []io.Closer
	var previous *ssh.Client
	for idx, hop := range chain {
		cfg, cfgClosers, err := c.buildClientConfig(ctx, hop, prompts)
		if err != nil {
			closeAll(closers)
			if previous != nil {
				_ = previous.Close()
			}
			return nil, nil, err
		}
		closers = append(closers, cfgClosers...)
		addr := net.JoinHostPort(hop.Hostname, strconv.Itoa(hop.Port))
		var conn net.Conn
		if idx == 0 {
			conn, err = c.dialBase(ctx, hop, addr)
		} else {
			conn, err = previous.Dial("tcp", addr)
		}
		if err != nil {
			closeAll(closers)
			if previous != nil {
				_ = previous.Close()
			}
			return nil, nil, err
		}
		clientConn, chans, reqs, err := ssh.NewClientConn(conn, addr, cfg)
		if err != nil {
			closeAll(closers)
			if previous != nil {
				_ = previous.Close()
			}
			return nil, nil, err
		}
		client := ssh.NewClient(clientConn, chans, reqs)
		closers = append(closers, client)
		previous = client
	}
	if previous == nil {
		return nil, nil, errors.New("empty SSH chain")
	}
	return previous, closers, nil
}

func (c *Connector) buildJumpChain(ctx context.Context, resolved domain.ResolvedConfig, prompts Prompts) ([]domain.ResolvedConfig, error) {
	chain := make([]domain.ResolvedConfig, 0, len(resolved.Route.ProxyJump)+1)
	for _, hop := range resolved.Route.ProxyJump {
		jump, err := c.resolveJumpSpec(ctx, hop, resolved, prompts)
		if err != nil {
			return nil, err
		}
		chain = append(chain, jump)
	}
	chain = append(chain, resolved)
	return chain, nil
}

func (c *Connector) resolveJumpSpec(ctx context.Context, spec string, fallback domain.ResolvedConfig, prompts Prompts) (domain.ResolvedConfig, error) {
	host, err := c.Catalog.FindHost(ctx, spec)
	if err == nil {
		resolved, err := c.Catalog.ResolveHost(ctx, host.ID)
		if err != nil {
			return domain.ResolvedConfig{}, err
		}
		return c.prepareResolved(ctx, resolved, prompts)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.ResolvedConfig{}, err
	}
	username, hostname, port := parseUserHostPort(spec, fallback.Username)
	out := fallback
	out.Label = spec
	out.HostID = ""
	out.Hostname = hostname
	out.Port = port
	out.Username = username
	out.Route.ProxyJump = nil
	return out, nil
}

func (c *Connector) buildClientConfig(ctx context.Context, resolved domain.ResolvedConfig, prompts Prompts) (*ssh.ClientConfig, []io.Closer, error) {
	auths, err := c.buildAuthMethods(ctx, resolved, prompts)
	if err != nil {
		return nil, nil, err
	}
	hostKeyAlgorithms := defaultPreferredHostKeyAlgorithms()
	callback := ssh.InsecureIgnoreHostKey()
	closers := []io.Closer{}
	if resolved.KnownHosts.Policy != domain.KnownHostsOff {
		verifier, err := prepareKnownHostsVerifier(ctx, c.Catalog, resolved, c.DefaultKnownHosts)
		if err != nil {
			return nil, nil, err
		}
		closers = append(closers, verifier)
		hostKeyAlgorithms = verifier.PreferredAlgorithms(net.JoinHostPort(resolved.Hostname, strconv.Itoa(resolved.Port)), nil)
		callback = c.hostKeyCallback(ctx, resolved, prompts, verifier)
		c.logf(2, "known_hosts policy=%s backend=%s preferred_hostkeys=%s", resolved.KnownHosts.Policy, resolved.KnownHosts.Backend, strings.Join(hostKeyAlgorithms, ","))
	} else {
		c.logf(2, "known_hosts policy=off")
	}
	return &ssh.ClientConfig{
		User:              resolved.Username,
		Auth:              auths,
		HostKeyCallback:   callback,
		HostKeyAlgorithms: hostKeyAlgorithms,
		Timeout:           20 * time.Second,
	}, closers, nil
}

func (c *Connector) buildAuthMethods(ctx context.Context, resolved domain.ResolvedConfig, prompts Prompts) ([]ssh.AuthMethod, error) {
	auths := make([]ssh.AuthMethod, 0, len(resolved.AuthMethods))
	for _, method := range resolved.AuthMethods {
		switch method.Type {
		case domain.AuthMethodPassword:
			password := method.Password
			if method.PasswordSecretID != "" {
				raw, err := c.Catalog.OpenSecret(ctx, method.PasswordSecretID)
				if err != nil {
					return nil, err
				}
				password = string(raw)
			}
			if password == "" && prompts.Secret != nil {
				value, err := prompts.Secret("Password")
				if err != nil {
					return nil, err
				}
				password = value
			}
			if password != "" {
				auths = append(auths, ssh.Password(password))
				c.logf(3, "enabled auth method: password")
			}
		case domain.AuthMethodKey:
			key, err := c.Catalog.GetKey(ctx, method.KeyID)
			if err != nil {
				return nil, err
			}
			signer, err := c.loadSigner(ctx, key, prompts)
			if err != nil {
				return nil, err
			}
			auths = append(auths, ssh.PublicKeys(signer))
			c.logf(3, "enabled auth method: key %s", key.Name)
		case domain.AuthMethodAgent:
			socket := method.AgentSocket
			if socket == "" {
				socket = os.Getenv("SSH_AUTH_SOCK")
			}
			conn, err := dialAgent(socket)
			if err != nil {
				return nil, err
			}
			auths = append(auths, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
			c.logf(3, "enabled auth method: agent socket=%s", socket)
		}
	}
	if len(auths) == 0 {
		return nil, errors.New("no usable SSH auth method")
	}
	return auths, nil
}

func (c *Connector) loadSigner(ctx context.Context, key *domain.Key, prompts Prompts) (ssh.Signer, error) {
	var privateKey []byte
	if key.PrivateKeySecretID != "" {
		raw, err := c.Catalog.OpenSecret(ctx, key.PrivateKeySecretID)
		if err != nil {
			return nil, err
		}
		privateKey = raw
	} else if key.SourcePath != "" {
		raw, err := os.ReadFile(config.ExpandUser(key.SourcePath))
		if err != nil {
			return nil, err
		}
		privateKey = raw
	}
	if len(privateKey) == 0 {
		return nil, errors.New("private key material is empty")
	}
	var passphrase []byte
	if key.PassphraseSecretID != "" {
		raw, err := c.Catalog.OpenSecret(ctx, key.PassphraseSecretID)
		if err != nil {
			return nil, err
		}
		passphrase = raw
	}
	if len(passphrase) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(privateKey, passphrase)
	}
	signer, err := ssh.ParsePrivateKey(privateKey)
	if err == nil {
		return signer, nil
	}
	if prompts.Secret == nil {
		return nil, err
	}
	value, promptErr := prompts.Secret(fmt.Sprintf("Passphrase for key %s", key.Name))
	if promptErr != nil {
		return nil, promptErr
	}
	return ssh.ParsePrivateKeyWithPassphrase(privateKey, []byte(value))
}

func (c *Connector) hostKeyCallback(ctx context.Context, resolved domain.ResolvedConfig, prompts Prompts, verifier *knownHostsVerifier) ssh.HostKeyCallback {
	cfg := effectiveKnownHostsConfig(resolved, c.DefaultKnownHosts)
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := verifier.callback(hostname, remote, key)
		if err == nil {
			c.logf(2, "verified host key %s for %s", key.Type(), knownHostPromptTarget(hostname))
			return nil
		}
		var keyErr *knownhosts.KeyError
		if !errors.As(err, &keyErr) || len(keyErr.Want) != 0 {
			c.logf(1, "host key verification failed for %s with %s: %v", knownHostPromptTarget(hostname), key.Type(), err)
			return err
		}
		switch cfg.Policy {
		case domain.KnownHostsAcceptNew:
			c.logf(1, "accepting new host key %s for %s into %s", key.Type(), knownHostPromptTarget(hostname), cfg.WriteSource)
			return verifier.Save(ctx, c.Catalog, hostname, remote, key)
		case domain.KnownHostsStrict:
			if prompts.Confirm == nil {
				return err
			}
			message := fmt.Sprintf(
				"Unknown host key for %s (%s)\nAlgorithm: %s\nFingerprint: %s\nTrust this host and add it to %s",
				knownHostPromptTarget(hostname),
				remote.String(),
				key.Type(),
				ssh.FingerprintSHA256(key),
				cfg.WriteSource,
			)
			approved, confirmErr := prompts.Confirm(message)
			if confirmErr != nil {
				return confirmErr
			}
			if !approved {
				return errors.New("host key was not trusted")
			}
			c.logf(1, "accepted new host key %s for %s into %s", key.Type(), knownHostPromptTarget(hostname), cfg.WriteSource)
			return verifier.Save(ctx, c.Catalog, hostname, remote, key)
		default:
			return err
		}
	}
}

func (c *Connector) dialBase(ctx context.Context, resolved domain.ResolvedConfig, addr string) (net.Conn, error) {
	if resolved.Route.OutboundProxy == nil {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", addr)
	}
	proxyCfg := resolved.Route.OutboundProxy
	if proxyCfg.Password == "" && proxyCfg.PasswordSecretID != "" {
		raw, err := c.Catalog.OpenSecret(ctx, proxyCfg.PasswordSecretID)
		if err != nil {
			return nil, err
		}
		proxyCfg.Password = string(raw)
	}
	switch proxyCfg.Type {
	case domain.ProxySOCKS5:
		var auth *xproxy.Auth
		if proxyCfg.Username != "" {
			auth = &xproxy.Auth{User: proxyCfg.Username, Password: proxyCfg.Password}
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyCfg.Address, auth, xproxy.Direct)
		if err != nil {
			return nil, err
		}
		return dialer.Dial("tcp", addr)
	case domain.ProxyHTTP:
		return dialHTTPProxy(ctx, proxyCfg, addr)
	default:
		return nil, fmt.Errorf("unsupported outbound proxy type %s", proxyCfg.Type)
	}
}

func (c *Connector) startForwards(ctx context.Context, client *ssh.Client, forwards []domain.Forward) ([]io.Closer, error) {
	closers := []io.Closer{}
	for _, forward := range forwards {
		if !forward.Enabled {
			continue
		}
		var (
			closer io.Closer
			err    error
		)
		switch forward.Type {
		case domain.ForwardLocal:
			closer, err = startLocalForward(ctx, client, forward)
		case domain.ForwardRemote:
			closer, err = startRemoteForward(ctx, client, forward)
		case domain.ForwardDynamic:
			closer, err = startDynamicForward(ctx, client, forward)
		default:
			err = fmt.Errorf("unsupported forward type %s", forward.Type)
		}
		if err != nil {
			closeAll(closers)
			return nil, err
		}
		closers = append(closers, closer)
	}
	return closers, nil
}

func startLocalForward(ctx context.Context, client *ssh.Client, forward domain.Forward) (io.Closer, error) {
	listenAddr := net.JoinHostPort(defaultListenHost(forward.ListenHost), strconv.Itoa(forward.ListenPort))
	targetAddr := net.JoinHostPort(forward.TargetHost, strconv.Itoa(forward.TargetPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ctx, ln, func(conn net.Conn) {
		remote, err := client.Dial("tcp", targetAddr)
		if err != nil {
			_ = conn.Close()
			return
		}
		pipeBoth(conn, remote)
	})
	return ln, nil
}

func startRemoteForward(ctx context.Context, client *ssh.Client, forward domain.Forward) (io.Closer, error) {
	listenAddr := net.JoinHostPort(defaultListenHost(forward.ListenHost), strconv.Itoa(forward.ListenPort))
	targetAddr := net.JoinHostPort(forward.TargetHost, strconv.Itoa(forward.TargetPort))
	ln, err := client.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ctx, ln, func(conn net.Conn) {
		local, err := net.Dial("tcp", targetAddr)
		if err != nil {
			_ = conn.Close()
			return
		}
		pipeBoth(conn, local)
	})
	return ln, nil
}

func startDynamicForward(ctx context.Context, client *ssh.Client, forward domain.Forward) (io.Closer, error) {
	listenAddr := net.JoinHostPort(defaultListenHost(forward.ListenHost), strconv.Itoa(forward.ListenPort))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	go acceptLoop(ctx, ln, func(conn net.Conn) {
		if err := handleSOCKS5(client, conn); err != nil {
			_ = conn.Close()
		}
	})
	return ln, nil
}

func parseUserHostPort(spec, fallbackUser string) (string, string, int) {
	username := fallbackUser
	hostPart := spec
	if at := strings.Index(spec, "@"); at >= 0 {
		username = spec[:at]
		hostPart = spec[at+1:]
	}
	port := 22
	if host, rawPort, err := net.SplitHostPort(hostPart); err == nil {
		hostPart = host
		if value, convErr := strconv.Atoi(rawPort); convErr == nil {
			port = value
		}
	} else if idx := strings.LastIndex(hostPart, ":"); idx > 0 {
		if value, convErr := strconv.Atoi(hostPart[idx+1:]); convErr == nil {
			port = value
			hostPart = hostPart[:idx]
		}
	}
	return username, hostPart, port
}

func dialHTTPProxy(ctx context.Context, proxyCfg *domain.OutboundProxy, targetAddr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", proxyCfg.Address)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+targetAddr, nil)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	req.Host = targetAddr
	if proxyCfg.Username != "" {
		auth := proxyCfg.Username + ":" + proxyCfg.Password
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	}
	if err := req.Write(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
	}
	return conn, nil
}

func handleSOCKS5(client *ssh.Client, conn net.Conn) error {
	reader := bufio.NewReader(conn)
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	if header[0] != 0x05 {
		return errors.New("unsupported SOCKS version")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(reader, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(reader, req); err != nil {
		return err
	}
	if req[1] != 0x01 {
		return errors.New("unsupported SOCKS command")
	}
	target, err := readSOCKSAddress(reader, req[3])
	if err != nil {
		return err
	}
	remote, err := client.Dial("tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		_ = remote.Close()
		return err
	}
	pipeBoth(conn, remote)
	return nil
}

func readSOCKSAddress(reader *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 6)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:4]).String()
		port := int(buf[4])<<8 | int(buf[5])
		return net.JoinHostPort(ip, strconv.Itoa(port)), nil
	case 0x03:
		length, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, int(length)+2)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		host := string(buf[:length])
		port := int(buf[length])<<8 | int(buf[length+1])
		return net.JoinHostPort(host, strconv.Itoa(port)), nil
	case 0x04:
		buf := make([]byte, 18)
		if _, err := io.ReadFull(reader, buf); err != nil {
			return "", err
		}
		ip := net.IP(buf[:16]).String()
		port := int(buf[16])<<8 | int(buf[17])
		return net.JoinHostPort(ip, strconv.Itoa(port)), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS atyp %d", atyp)
	}
}

func acceptLoop(ctx context.Context, ln net.Listener, handler func(net.Conn)) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handler(conn)
	}
}

func pipeBoth(left, right net.Conn) {
	go func() {
		_, _ = io.Copy(left, right)
		_ = left.Close()
		_ = right.Close()
	}()
	go func() {
		_, _ = io.Copy(right, left)
		_ = left.Close()
		_ = right.Close()
	}()
}

func defaultListenHost(host string) string {
	if host == "" {
		return "127.0.0.1"
	}
	return host
}

func filepathDir(path string) string {
	idx := strings.LastIndexAny(path, `/\`)
	if idx < 0 {
		return "."
	}
	return path[:idx]
}

func ensureKnownHostsFile(path string) error {
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
		return err
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return os.WriteFile(path, nil, 0o600)
	} else {
		return err
	}
}

func appendKnownHost(path, hostname string, remote net.Addr, key ssh.PublicKey) error {
	if err := ensureKnownHostsFile(path); err != nil {
		return err
	}
	addresses := knownHostAddresses(hostname, remote)
	line := knownhosts.Line(addresses, key)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.WriteString(file, line+"\n")
	return err
}

func knownHostAddresses(hostname string, remote net.Addr) []string {
	addresses := []string{}
	appendIfMissing := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		for _, existing := range addresses {
			if existing == value {
				return
			}
		}
		addresses = append(addresses, value)
	}
	appendIfMissing(hostname)
	if remote != nil {
		appendIfMissing(remote.String())
	}
	return addresses
}

func knownHostPromptTarget(hostname string) string {
	if hostname == "" {
		return "<unknown>"
	}
	return knownhosts.Normalize(hostname)
}

func (c *Connector) logf(level int, format string, args ...any) {
	if c == nil || c.Verbosity < level {
		return
	}
	fmt.Fprintf(os.Stderr, "debug%d: %s\n", level, fmt.Sprintf(format, args...))
}

func consoleTerminalSize() (int, int) {
	return detectTerminalSizeFromFDs(
		[]int{int(os.Stdout.Fd()), int(os.Stderr.Fd()), int(os.Stdin.Fd())},
		term.GetSize,
		120,
		32,
	)
}

func detectTerminalSizeFromFDs(fds []int, getSize func(fd int) (width, height int, err error), fallbackWidth, fallbackHeight int) (int, int) {
	for _, fd := range fds {
		if fd < 0 {
			continue
		}
		width, height, err := getSize(fd)
		if err == nil && width > 0 && height > 0 {
			return width, height
		}
	}
	return fallbackWidth, fallbackHeight
}

func (c *Connector) watchConsoleResize(ctx context.Context, interval time.Duration, onResize func(cols, rows int)) {
	if onResize == nil {
		return
	}
	watchTerminalResize(ctx, interval, consoleTerminalSize, onResize)
}

func watchTerminalResize(ctx context.Context, interval time.Duration, currentSize func() (int, int), onResize func(cols, rows int)) {
	if currentSize == nil || onResize == nil {
		return
	}
	lastCols, lastRows := currentSize()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cols, rows := currentSize()
			if cols <= 0 || rows <= 0 {
				continue
			}
			if cols == lastCols && rows == lastRows {
				continue
			}
			lastCols, lastRows = cols, rows
			onResize(cols, rows)
		}
	}
}

func closeAll(closers []io.Closer) error {
	var out error
	for _, closer := range closers {
		if closer == nil {
			continue
		}
		if err := closer.Close(); err != nil && out == nil {
			out = err
		}
	}
	return out
}
