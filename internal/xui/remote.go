package xui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	posixpath "path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHConfig struct {
	Host          string
	User          string
	Port          int
	KeyPath       string
	KeyPassphrase string
	Password      string
}

type Remote interface {
	Run(ctx context.Context, command string) (string, error)
	Upload(ctx context.Context, path string, data []byte, perm os.FileMode) error
	Tunnel(ctx context.Context, remoteHost string, remotePort int) (Tunnel, error)
	Close() error
}

type Tunnel struct {
	LocalAddr string
	Close     func() error
}

type RemoteFactory func(ctx context.Context, cfg SSHConfig) (Remote, error)

type SSHRemote struct {
	client *ssh.Client
}

func DialSSH(ctx context.Context, cfg SSHConfig) (Remote, error) {
	cfg = normalizeSSH(cfg)
	auth, err := authMethods(cfg)
	if err != nil {
		return nil, err
	}
	if len(auth) == 0 {
		return nil, fmt.Errorf("no SSH authentication method available; provide --ssh-key or --ssh-password")
	}
	clientConfig := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            auth,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         12 * time.Second,
	}
	addr := net.JoinHostPort(cfg.Host, fmt.Sprintf("%d", cfg.Port))
	type result struct {
		client *ssh.Client
		err    error
	}
	ch := make(chan result, 1)
	go func() {
		client, err := ssh.Dial("tcp", addr, clientConfig)
		ch <- result{client: client, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-ch:
		if got.err != nil {
			return nil, fmt.Errorf("connect SSH %s@%s: %w", cfg.User, addr, got.err)
		}
		return &SSHRemote{client: got.client}, nil
	}
}

func normalizeSSH(cfg SSHConfig) SSHConfig {
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.User = strings.TrimSpace(cfg.User)
	if cfg.User == "" {
		cfg.User = "root"
	}
	if cfg.Port == 0 {
		cfg.Port = 22
	}
	cfg.KeyPath = expandHome(strings.TrimSpace(cfg.KeyPath))
	return cfg
}

func authMethods(cfg SSHConfig) ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod
	if cfg.Password != "" {
		methods = append(methods, ssh.Password(cfg.Password))
	}
	if cfg.KeyPath != "" {
		signer, err := signerFromFile(cfg.KeyPath, cfg.KeyPassphrase)
		if err != nil {
			return nil, err
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}
	for _, path := range defaultKeyPaths() {
		if path == cfg.KeyPath {
			continue
		}
		signer, err := signerFromFile(path, "")
		if err == nil {
			methods = append(methods, ssh.PublicKeys(signer))
		}
	}
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			methods = append(methods, ssh.PublicKeysCallback(agent.NewClient(conn).Signers))
		}
	}
	return methods, nil
}

func signerFromFile(path, passphrase string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SSH key %s: %w", path, err)
	}
	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("decrypt SSH key %s: %w", path, err)
		}
		return signer, nil
	}
	signer, err = ssh.ParsePrivateKey(data)
	if err != nil {
		var missing *ssh.PassphraseMissingError
		if errors.As(err, &missing) {
			return nil, fmt.Errorf("SSH key %s requires a passphrase: %w", path, err)
		}
		return nil, fmt.Errorf("parse SSH key %s: %w", path, err)
	}
	return signer, nil
}

func defaultKeyPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	return []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
		filepath.Join(home, ".ssh", "id_ecdsa"),
	}
}

func expandHome(path string) string {
	if path == "" || path == "~" {
		if path == "~" {
			if home, err := os.UserHomeDir(); err == nil {
				return home
			}
		}
		return path
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func (r *SSHRemote) Run(ctx context.Context, command string) (string, error) {
	session, err := r.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return "", ctx.Err()
	case err := <-done:
		out := stdout.String()
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = strings.TrimSpace(out)
			}
			if msg == "" {
				msg = err.Error()
			}
			return out, fmt.Errorf("remote command failed: %s", msg)
		}
		return out, nil
	}
}

func (r *SSHRemote) Upload(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	session, err := r.client.NewSession()
	if err != nil {
		return fmt.Errorf("open SSH session: %w", err)
	}
	defer session.Close()
	tmp := path + ".tmp"
	session.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	session.Stderr = &stderr
	cmd := remoteUploadCommand(path, tmp, perm)
	done := make(chan error, 1)
	go func() {
		done <- session.Run(cmd)
	}()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		return ctx.Err()
	case err := <-done:
		if err != nil {
			msg := strings.TrimSpace(stderr.String())
			if msg == "" {
				msg = err.Error()
			}
			return fmt.Errorf("upload %s: %s", path, msg)
		}
		return nil
	}
}

func remoteUploadCommand(remotePath, tmpPath string, perm os.FileMode) string {
	return "sh -lc " + shQuote(remoteUploadScript(remotePath, tmpPath, perm))
}

func remoteUploadScript(remotePath, tmpPath string, perm os.FileMode) string {
	parent := posixpath.Dir(remotePath)
	return "set -u\n" +
		"parent=" + shQuote(parent) + "\n" +
		"tmp=" + shQuote(tmpPath) + "\n" +
		"target=" + shQuote(remotePath) + "\n" +
		"if ! mkdir -p \"$parent\"; then\n" +
		"  echo \"remote upload parent is not writable: $parent\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if [ ! -d \"$parent\" ]; then\n" +
		"  echo \"remote upload parent does not exist: $parent\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if [ ! -w \"$parent\" ]; then\n" +
		"  echo \"remote upload parent is not writable: $parent\" >&2\n" +
		"  exit 1\n" +
		"fi\n" +
		"if ! cat > \"$tmp\"; then\n" +
		"  echo \"remote upload temp write failed: $tmp\" >&2\n" +
		"  rm -f \"$tmp\"\n" +
		"  exit 1\n" +
		"fi\n" +
		fmt.Sprintf("chmod %04o \"$tmp\"\n", perm.Perm()) +
		"mv -f \"$tmp\" \"$target\""
}

func (r *SSHRemote) Tunnel(ctx context.Context, remoteHost string, remotePort int) (Tunnel, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return Tunnel{}, fmt.Errorf("open local tunnel listener: %w", err)
	}
	remoteAddr := net.JoinHostPort(remoteHost, fmt.Sprintf("%d", remotePort))
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			local, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer local.Close()
				remote, err := r.client.Dial("tcp", remoteAddr)
				if err != nil {
					return
				}
				defer remote.Close()
				copyBoth(local, remote)
			}()
		}
	}()
	closeFn := func() error {
		err := listener.Close()
		select {
		case <-done:
		case <-ctx.Done():
			if err == nil {
				err = ctx.Err()
			}
		}
		return err
	}
	return Tunnel{LocalAddr: listener.Addr().String(), Close: closeFn}, nil
}

func copyBoth(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		done <- struct{}{}
	}()
	<-done
}

func (r *SSHRemote) Close() error {
	if r == nil || r.client == nil {
		return nil
	}
	err := r.client.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func shQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
