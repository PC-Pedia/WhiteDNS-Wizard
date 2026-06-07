package xui

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/whitedns/wdns-wizard/internal/acme"
	"github.com/whitedns/wdns-wizard/internal/cloudflare"
	"github.com/whitedns/wdns-wizard/internal/credentials"
	"github.com/whitedns/wdns-wizard/internal/output"
	"github.com/whitedns/wdns-wizard/pkg/types"
)

type ACMEPreflightChecker interface {
	Check(ctx context.Context, input acme.PreflightInput) error
}

type Provisioner struct {
	RemoteFactory       RemoteFactory
	Issuer              acme.Issuer
	ACMEPreflight       ACMEPreflightChecker
	APIClient           func(baseURL, basePath string) (*APIClient, error)
	RealitySNIValidator RealitySNIValidator
}

func NewProvisioner() Provisioner {
	return Provisioner{
		RemoteFactory: DialSSH,
		Issuer:        acme.LegoIssuer{},
		ACMEPreflight: acme.PreflightChecker{},
		APIClient:     NewAPIClient,
	}
}

type progressRecorder struct {
	lines    []string
	path     string
	callback func(string)
}

func newProgressRecorder(callback func(string)) *progressRecorder {
	return &progressRecorder{callback: callback}
}

func (r *progressRecorder) SetPath(path string) {
	r.path = path
	if r.path == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(r.path), 0o755)
	_ = os.WriteFile(r.path, []byte(r.Body()), 0o644)
}

func (r *progressRecorder) Log(message string) {
	line := time.Now().UTC().Format(time.RFC3339) + "  " + strings.TrimSpace(message)
	r.lines = append(r.lines, line)
	if r.callback != nil {
		r.callback(line)
	}
	if r.path != "" {
		_ = os.WriteFile(r.path, []byte(r.Body()), 0o644)
	}
}

func (r *progressRecorder) Logf(format string, args ...any) {
	r.Log(fmt.Sprintf(format, args...))
}

func (r *progressRecorder) Body() string {
	if len(r.lines) == 0 {
		return ""
	}
	return strings.Join(r.lines, "\n") + "\n"
}

func (p Provisioner) Plan(ctx context.Context, input Input) (types.XUIPlan, error) {
	project, bundle, remote, info, err := p.prepare(ctx, input, prepareOptions{})
	if remote != nil {
		_ = remote.Close()
	}
	if err != nil {
		return types.XUIPlan{}, err
	}
	plan := buildPlan(project.Domain, input, info, bundle, nil)
	if info.ExistingDocker3XUI && credentialsProvidedOrSaved(input.Panel, project.Secrets) {
		conflicts, warnings, err := p.detectPanelConflicts(ctx, input, project, bundle)
		if err != nil {
			if info.ManagedDocker3XUI {
				warnings = append(warnings, "Managed 3x-ui API is not available yet; apply will repair/restart the managed Docker stack before final conflict detection: "+err.Error())
			} else {
				warnings = append(warnings, "Could not inspect 3x-ui API conflicts: "+err.Error())
			}
		}
		plan.Conflicts = conflicts
		plan.Warnings = append(plan.Warnings, warnings...)
	}
	return plan, nil
}

func (p Provisioner) Apply(ctx context.Context, input Input) (Result, error) {
	progress := newProgressRecorder(input.Progress)
	progress.Log("Preparing project and connecting to VPS over SSH.")
	project, bundle, remote, info, err := p.prepare(ctx, input, prepareOptions{
		ValidateRealitySNIs: true,
		Progress:            progress,
		RealitySNIValidator: p.RealitySNIValidator,
	})
	if err != nil {
		return Result{}, err
	}
	progress.SetPath(project.Paths.XUILog)
	progress.Logf("Connected to %s. Docker installed: %t. Managed 3x-ui: %t.", input.SSH.Host, info.DockerInstalled, info.ManagedDocker3XUI)
	defer remote.Close()

	if err := p.preflightCertificatesIfNeeded(ctx, project, progress); err != nil {
		return Result{}, err
	}

	plan := buildPlan(project.Domain, input, info, bundle, nil)
	installed := false
	if info.ExistingNonDockerXUI && !info.ExistingDocker3XUI {
		return Result{}, fmt.Errorf("non-Docker 3x-ui install detected; automatic migration is not supported")
	}
	if !info.ExistingDocker3XUI {
		progress.Log("Installing managed Docker 3x-ui stack with PostgreSQL.")
		if changed, err := project.ensureGeneratedPanelCredentials(); err != nil {
			return Result{}, err
		} else if changed {
			if err := project.saveSecrets(); err != nil {
				return Result{}, err
			}
		}
		progress.Logf("Preparing remote managed directory %s and compose file %s.", RemoteBaseDir, RemoteComposePath)
		if err := InstallDocker3XUI(ctx, remote, project.Secrets); err != nil {
			return Result{}, err
		}
		installed = true
		info.ExistingDocker3XUI = true
		info.ContainerName = "3xui_app"
		info.ManagedDocker3XUI = true
	} else if info.ManagedDocker3XUI {
		progress.Log("Repairing/recreating managed Docker 3x-ui service.")
		if changed, err := project.ensureGeneratedPanelCredentials(); err != nil {
			return Result{}, err
		} else if changed {
			if err := project.saveSecrets(); err != nil {
				return Result{}, err
			}
		}
		progress.Logf("Preparing remote managed directory %s and compose file %s.", RemoteBaseDir, RemoteComposePath)
		if err := EnsureManagedDocker3XUI(ctx, remote, project.Secrets); err != nil {
			return Result{}, err
		}
	}
	progress.Log("Applying firewall rules for panel and proxy ports.")
	firewallWarnings := ApplyFirewall(ctx, remote)
	plan.Warnings = append(plan.Warnings, firewallWarnings...)

	panel := panelFromInputOrSecrets(input.Panel, project.Secrets)
	progress.Log("Opening SSH tunnel to local 3x-ui panel API.")
	tunnel, err := remote.Tunnel(ctx, "127.0.0.1", PanelPort)
	if err != nil {
		return Result{}, err
	}
	defer tunnel.Close()
	apiFactory := p.APIClient
	if apiFactory == nil {
		apiFactory = NewAPIClient
	}
	api, err := apiFactory("http://"+tunnel.LocalAddr, panel.WebBasePath)
	if err != nil {
		return Result{}, err
	}
	progress.Log("Waiting for 3x-ui panel login.")
	if err := retry(ctx, 60, time.Second, func() error {
		return api.Login(ctx, panel.Username, panel.Password)
	}); err != nil {
		return Result{}, fmt.Errorf("validate 3x-ui panel login: %w", err)
	}

	progress.Log("Reading existing 3x-ui inbounds and Xray outbounds.")
	inbounds, err := api.ListInbounds(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("list 3x-ui inbounds: %w", err)
	}
	xrayConfig, outboundTestURL, err := api.GetXrayConfig(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("read xray outbound config: %w", err)
	}
	conflicts := DetectConflicts(inbounds, xrayConfig, bundle.Inbounds)
	plan.Conflicts = conflicts
	if len(conflicts) > 0 && !input.ConfirmReplace {
		return Result{}, ConflictError{Conflicts: conflicts, Warnings: plan.Warnings}
	}

	if err := p.ensureCertificates(ctx, project, input, progress); err != nil {
		return Result{}, err
	}
	progress.Log("Uploading Origin CA and public ACME certificates to the VPS.")
	if err := uploadCertificates(ctx, remote, project.Paths); err != nil {
		return Result{}, err
	}

	progress.Log("Replacing WhiteDNS-managed inbounds and outbounds.")
	for _, id := range matchingInboundIDs(inbounds, bundle.Inbounds) {
		if err := api.DeleteInbound(ctx, id); err != nil {
			return Result{}, fmt.Errorf("delete conflicting 3x-ui inbound %d: %w", id, err)
		}
	}
	xrayConfig = EnsureOutbounds(xrayConfig)
	if err := api.UpdateXrayConfig(ctx, xrayConfig, outboundTestURL); err != nil {
		return Result{}, fmt.Errorf("update xray outbounds: %w", err)
	}
	var inboundStates []types.XUIInboundState
	for _, inbound := range bundle.Inbounds {
		if _, err := api.AddInbound(ctx, inbound); err != nil {
			return Result{}, fmt.Errorf("add 3x-ui inbound %s: %w", inbound.Tag, err)
		}
		inboundStates = append(inboundStates, types.XUIInboundState{
			Tag:      inbound.Tag,
			Protocol: inbound.Protocol,
			Hostname: hostnameForTag(bundle.Plan.Protocols, inbound.Tag),
			Port:     inbound.Port,
			Network:  networkForTag(bundle.Plan.Protocols, inbound.Tag),
		})
	}
	if err := api.RestartXray(ctx); err != nil {
		plan.Warnings = append(plan.Warnings, "3x-ui API did not confirm Xray restart: "+err.Error())
	}

	progress.Log("Writing local x-ui state and client links.")
	state := types.XUIState{
		Domain:        project.Domain,
		RemoteHost:    input.SSH.Host,
		ContainerName: firstNonEmpty(info.ContainerName, "3xui_app"),
		Installed:     installed,
		AppliedAt:     time.Now().UTC(),
		Inbounds:      inboundStates,
		Outbounds:     managedOutboundTags(),
		Warnings:      plan.Warnings,
	}
	publicCert, _ := os.ReadFile(project.Paths.PublicCert)
	publicKey, _ := os.ReadFile(project.Paths.PublicKey)
	progress.Log("3x-ui provisioning complete.")
	log := progress.Body() + "\n" + renderLog(plan, state)
	if err := output.WriteXUI(project.Paths, plan, state, bundle.Links, string(publicCert), string(publicKey), log); err != nil {
		return Result{}, err
	}
	return Result{
		Plan:       plan,
		State:      state,
		Links:      bundle.Links,
		ProjectDir: project.Paths.ProjectDir,
		PublicCert: string(publicCert),
		PublicKey:  string(publicKey),
		LogPath:    project.Paths.XUILog,
	}, nil
}

type prepareOptions struct {
	ValidateRealitySNIs bool
	Progress            *progressRecorder
	RealitySNIValidator RealitySNIValidator
}

func (p Provisioner) prepare(ctx context.Context, input Input, opts prepareOptions) (projectData, ProtocolBundle, Remote, RemoteInfo, error) {
	input.SSH = normalizeSSH(input.SSH)
	if err := validateSSHInput(input.SSH); err != nil {
		return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
	}
	project, err := loadProject(input.Root, input.Domain)
	if err != nil {
		return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
	}
	if changed, err := project.ensureXUISecrets(input.Panel); err != nil {
		return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
	} else if changed {
		if err := project.saveSecrets(); err != nil {
			return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
		}
	}
	if opts.ValidateRealitySNIs {
		if changed := project.ensureValidatedRealitySNIs(ctx, opts.RealitySNIValidator, opts.Progress); changed {
			if err := project.saveSecrets(); err != nil {
				return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
			}
		}
	}
	bundle, err := BuildProtocolBundle(project.Domain, project.Secrets)
	if err != nil {
		return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
	}
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
	}
	info, err := DetectRemote(ctx, remote)
	if err != nil {
		_ = remote.Close()
		return projectData{}, ProtocolBundle{}, nil, RemoteInfo{}, err
	}
	return project, bundle, remote, info, nil
}

func (p Provisioner) detectPanelConflicts(ctx context.Context, input Input, project projectData, bundle ProtocolBundle) ([]types.XUIConflict, []string, error) {
	remoteFactory := p.RemoteFactory
	if remoteFactory == nil {
		remoteFactory = DialSSH
	}
	remote, err := remoteFactory(ctx, input.SSH)
	if err != nil {
		return nil, nil, err
	}
	defer remote.Close()
	tunnel, err := remote.Tunnel(ctx, "127.0.0.1", PanelPort)
	if err != nil {
		return nil, nil, err
	}
	defer tunnel.Close()
	panel := panelFromInputOrSecrets(input.Panel, project.Secrets)
	apiFactory := p.APIClient
	if apiFactory == nil {
		apiFactory = NewAPIClient
	}
	api, err := apiFactory("http://"+tunnel.LocalAddr, panel.WebBasePath)
	if err != nil {
		return nil, nil, err
	}
	if err := api.Login(ctx, panel.Username, panel.Password); err != nil {
		return nil, nil, err
	}
	inbounds, err := api.ListInbounds(ctx)
	if err != nil {
		return nil, nil, err
	}
	xrayConfig, _, err := api.GetXrayConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	return DetectConflicts(inbounds, xrayConfig, bundle.Inbounds), nil, nil
}

func (p Provisioner) ensureCertificates(ctx context.Context, project projectData, input Input, progress *progressRecorder) error {
	progress.Log("Checking required Cloudflare Origin CA certificate files.")
	if _, err := os.Stat(project.Paths.OriginCert); err != nil {
		return fmt.Errorf("origin certificate is missing; run Cloudflare apply first: %w", err)
	}
	if _, err := os.Stat(project.Paths.OriginKey); err != nil {
		return fmt.Errorf("origin private key is missing; run Cloudflare apply first: %w", err)
	}
	coveredHostnames := publicACMECoveredHostnames(project.Domain)
	requestDomains := publicACMERequestDomains(project.Domain)
	if project.publicCertFresh(coveredHostnames) {
		progress.Logf("Using existing fresh public ACME certificate covering %s.", strings.Join(coveredHostnames, ", "))
		return nil
	}
	progress.Logf("Requesting wildcard public ACME certificate with DNS-01 for %s.", strings.Join(requestDomains, ", "))
	root := project.Root
	creds, err := credentials.Load(root)
	if err != nil {
		return err
	}
	if strings.TrimSpace(creds.APIToken) == "" {
		return acme.PreflightError{Kind: acme.PreflightKindToken, Domain: project.Domain, Detail: "saved Cloudflare API token is required for ACME DNS-01"}
	}
	if err := p.runACMEPreflight(ctx, project.Domain, creds, progress); err != nil {
		return err
	}
	issuer := p.Issuer
	if issuer == nil {
		issuer = acme.LegoIssuer{}
	}
	cert, err := issuer.Obtain(ctx, acme.Input{
		Email:           firstNonEmpty(input.ACMEEmail, "admin@"+project.Domain),
		CloudflareToken: creds.APIToken,
		Domains:         requestDomains,
	})
	if err != nil {
		return err
	}
	progress.Log("ACME certificate issued; saving public certificate locally.")
	if err := os.MkdirAll(filepath.Dir(project.Paths.PublicCert), 0o755); err != nil {
		return fmt.Errorf("create public cert directory: %w", err)
	}
	if err := os.WriteFile(project.Paths.PublicCert, []byte(cert.CertPEM), 0o644); err != nil {
		return fmt.Errorf("write public ACME certificate: %w", err)
	}
	if err := os.WriteFile(project.Paths.PublicKey, []byte(cert.KeyPEM), 0o600); err != nil {
		return fmt.Errorf("write public ACME key: %w", err)
	}
	return nil
}

func (p Provisioner) preflightCertificatesIfNeeded(ctx context.Context, project projectData, progress *progressRecorder) error {
	coveredHostnames := publicACMECoveredHostnames(project.Domain)
	if project.publicCertFresh(coveredHostnames) {
		progress.Logf("Skipping ACME DNS preflight because an existing fresh public certificate covers %s.", strings.Join(coveredHostnames, ", "))
		return nil
	}
	progress.Logf("Running ACME DNS preflight for %s before remote Docker changes.", project.Domain)
	creds, err := credentials.Load(project.Root)
	if err != nil {
		return err
	}
	if strings.TrimSpace(creds.APIToken) == "" {
		return acme.PreflightError{Kind: acme.PreflightKindToken, Domain: project.Domain, Detail: "saved Cloudflare API token is required for ACME DNS-01"}
	}
	return p.runACMEPreflight(ctx, project.Domain, creds, progress)
}

func (p Provisioner) runACMEPreflight(ctx context.Context, domain string, creds credentials.CloudflareCredentials, progress *progressRecorder) error {
	checker := p.ACMEPreflight
	if checker == nil {
		checker = acme.PreflightChecker{}
	}
	if err := checker.Check(ctx, acme.PreflightInput{
		Domain:      domain,
		ZoneChecker: cloudflare.NewSDKClient(creds.APIToken, creds.AccountID),
	}); err != nil {
		progress.Logf("ACME DNS preflight failed for %s: %s", domain, oneLine(err.Error()))
		return err
	}
	progress.Logf("ACME DNS preflight passed for %s.", domain)
	return nil
}

func publicACMERequestDomains(domain string) []string {
	return []string{"*." + domain}
}

func publicACMECoveredHostnames(domain string) []string {
	return []string{
		"direct." + domain,
		"hy2." + domain,
		"tor-vless-ws." + domain,
		"tor-vless-ws-8443." + domain,
		"tor-hy2." + domain,
		"tor-direct." + domain,
	}
}

func uploadCertificates(ctx context.Context, remote Remote, paths output.ProjectPaths) error {
	files := []struct {
		local  string
		remote string
		perm   os.FileMode
	}{
		{paths.OriginCert, HostOriginCertPath, 0o644},
		{paths.OriginKey, HostOriginKeyPath, 0o600},
		{paths.PublicCert, HostPublicCertPath, 0o644},
		{paths.PublicKey, HostPublicKeyPath, 0o600},
	}
	for _, file := range files {
		data, err := os.ReadFile(file.local)
		if err != nil {
			return fmt.Errorf("read %s: %w", file.local, err)
		}
		if err := remote.Upload(ctx, file.remote, data, file.perm); err != nil {
			return err
		}
	}
	return nil
}

func buildPlan(domain string, input Input, info RemoteInfo, bundle ProtocolBundle, conflicts []types.XUIConflict) types.XUIPlan {
	warnings := append([]string{}, info.Warnings...)
	if input.SSH.Host == "" {
		warnings = append(warnings, "SSH host is empty.")
	}
	return types.XUIPlan{
		Domain:          domain,
		InstallRequired: !info.ExistingDocker3XUI,
		Protocols:       bundle.Plan.Protocols,
		Conflicts:       conflicts,
		Warnings:        warnings,
		ComposePath:     RemoteComposePath,
		PlannedAt:       time.Now().UTC(),
		Remote: types.XUIRemotePlan{
			SSHHost:       input.SSH.Host,
			SSHUser:       firstNonEmpty(input.SSH.User, "root"),
			SSHPort:       input.SSH.Port,
			ContainerName: info.ContainerName,
			PanelPort:     PanelPort,
			WebBasePath:   panelFromInputOrSecrets(input.Panel, map[string]string{}).WebBasePath,
		},
	}
}

func panelFromInputOrSecrets(panel PanelCredentials, values map[string]string) PanelCredentials {
	username := firstNonEmpty(panel.Username, values["panel_username"], "admin")
	password := firstNonEmpty(panel.Password, values["panel_password"], "admin")
	basePath := firstNonEmpty(panel.WebBasePath, values["panel_base_path"], "/")
	return PanelCredentials{Username: username, Password: password, WebBasePath: normalizeBasePath(basePath)}
}

func credentialsProvidedOrSaved(panel PanelCredentials, values map[string]string) bool {
	return firstNonEmpty(panel.Username, values["panel_username"]) != "" && firstNonEmpty(panel.Password, values["panel_password"]) != ""
}

func hostnameForTag(protocols []types.Protocol, tag string) string {
	for _, proto := range protocols {
		if proto.Tag == tag {
			return proto.Hostname
		}
	}
	return ""
}

func networkForTag(protocols []types.Protocol, tag string) string {
	for _, proto := range protocols {
		if proto.Tag == tag {
			if proto.Network != "" {
				return proto.Network
			}
			if proto.UDP {
				return "udp"
			}
			return "tcp"
		}
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func retry(ctx context.Context, attempts int, delay time.Duration, fn func() error) error {
	var last error
	for i := 0; i < attempts; i++ {
		last = fn()
		if last == nil {
			return nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

func renderLog(plan types.XUIPlan, state types.XUIState) string {
	var b strings.Builder
	fmt.Fprintf(&b, "WhiteDNS x-ui provision completed at %s\n", state.AppliedAt.Format(time.RFC3339))
	fmt.Fprintf(&b, "domain: %s\n", state.Domain)
	fmt.Fprintf(&b, "remote: %s\n", state.RemoteHost)
	for _, inbound := range state.Inbounds {
		fmt.Fprintf(&b, "%s %s %s:%d/%s\n", inbound.Tag, inbound.Protocol, inbound.Hostname, inbound.Port, inbound.Network)
	}
	for _, warning := range plan.Warnings {
		fmt.Fprintf(&b, "warning: %s\n", warning)
	}
	return b.String()
}

func validateSSHInput(cfg SSHConfig) error {
	if strings.TrimSpace(cfg.Host) == "" {
		return fmt.Errorf("SSH host is required")
	}
	if cfg.Port < 0 || cfg.Port > 65535 {
		return fmt.Errorf("SSH port must be 1-65535")
	}
	if net.ParseIP(cfg.Host) == nil && strings.Contains(cfg.Host, "/") {
		return fmt.Errorf("SSH host must be a hostname or IP address")
	}
	return nil
}
