package domain

import (
	"errors"
	"fmt"
)

var ErrHostNotConnectable = errors.New("host configuration is incomplete")

type ResolvedConfig struct {
	HostID          string           `json:"host_id"`
	Label           string           `json:"label"`
	Hostname        string           `json:"hostname"`
	Port            int              `json:"port"`
	Username        string           `json:"username,omitempty"`
	IdentityRef     string           `json:"identity_ref,omitempty"`
	Identity        *Identity        `json:"identity,omitempty"`
	AuthMethods     []AuthMethod     `json:"auth_methods,omitempty"`
	Route           Route            `json:"route,omitempty"`
	KnownHosts      KnownHostsConfig `json:"known_hosts"`
	Forwards        []Forward        `json:"forwards,omitempty"`
	Missing         []string         `json:"missing,omitempty"`
	ResolutionTrace []string         `json:"resolution_trace,omitempty"`
}

type ResolveInputs struct {
	Host     Host
	Profiles []Profile
	Identity *Identity
	Forwards map[string]Forward
}

func ResolveHost(in ResolveInputs) (ResolvedConfig, error) {
	out := ResolvedConfig{
		HostID:          in.Host.ID,
		Label:           in.Host.Label(),
		Port:            22,
		KnownHosts:      KnownHostsConfig{Policy: KnownHostsStrict, Backend: KnownHostsBackendVaultFile},
		ResolutionTrace: make([]string, 0, len(in.Profiles)+3),
	}
	for _, profile := range in.Profiles {
		mergeProfile(&out, profile)
	}
	if in.Identity != nil {
		mergeIdentity(&out, *in.Identity)
	}
	mergeHost(&out, in.Host)
	out.AuthMethods = resolveAuthMethods(in.Host, in.Identity)
	if out.Hostname == "" {
		out.Missing = append(out.Missing, "hostname")
	}
	if out.Username == "" {
		out.Missing = append(out.Missing, "username")
	}
	if len(out.AuthMethods) == 0 {
		out.Missing = append(out.Missing, "authentication method")
	}
	out.Forwards = resolveForwards(in.Host.ForwardIDs, in.Profiles, in.Forwards)
	if len(out.Missing) > 0 {
		return out, ErrHostNotConnectable
	}
	return out, nil
}

func mergeProfile(out *ResolvedConfig, profile Profile) {
	out.ResolutionTrace = append(out.ResolutionTrace, fmt.Sprintf("profile %s applied", profile.Name))
	if profile.Port != nil {
		out.Port = *profile.Port
	}
	if profile.Username != nil && *profile.Username != "" {
		out.Username = *profile.Username
	}
	if profile.IdentityRef != nil && *profile.IdentityRef != "" {
		out.IdentityRef = *profile.IdentityRef
	}
	if profile.KnownHosts != nil {
		out.KnownHosts = *profile.KnownHosts
		if out.KnownHosts.Policy == "" {
			out.KnownHosts.Policy = KnownHostsStrict
		}
		if out.KnownHosts.Backend == "" {
			out.KnownHosts.Backend = KnownHostsBackendVaultFile
		}
	}
	out.Route = mergeRoute(out.Route, profile.Route)
}

func mergeIdentity(out *ResolvedConfig, identity Identity) {
	out.Identity = cloneIdentity(&identity)
	out.IdentityRef = identity.ID
	if identity.Username != "" {
		out.Username = identity.Username
	}
	out.ResolutionTrace = append(out.ResolutionTrace, fmt.Sprintf("identity %s supplied username/auth defaults", identity.Name))
}

func mergeHost(out *ResolvedConfig, host Host) {
	out.ResolutionTrace = append(out.ResolutionTrace, fmt.Sprintf("host %s overrides applied", host.Label()))
	out.Hostname = host.Hostname
	if host.Port != nil {
		out.Port = *host.Port
	}
	if host.Username != nil && *host.Username != "" {
		out.Username = *host.Username
	}
	if host.IdentityRef != nil && *host.IdentityRef != "" {
		out.IdentityRef = *host.IdentityRef
	}
	if host.KnownHosts != nil {
		out.KnownHosts = *host.KnownHosts
		if out.KnownHosts.Policy == "" {
			out.KnownHosts.Policy = KnownHostsStrict
		}
		if out.KnownHosts.Backend == "" {
			out.KnownHosts.Backend = KnownHostsBackendVaultFile
		}
	}
	out.Route = mergeRoute(out.Route, host.Route)
}

func resolveAuthMethods(host Host, identity *Identity) []AuthMethod {
	methods := make([]AuthMethod, 0, 2)
	if host.KeyRef != nil && *host.KeyRef != "" {
		methods = append(methods, AuthMethod{
			Type:  AuthMethodKey,
			KeyID: *host.KeyRef,
		})
	}
	if host.Password != "" || host.PasswordSecretID != "" {
		methods = append(methods, AuthMethod{
			Type:             AuthMethodPassword,
			Password:         host.Password,
			PasswordSecretID: host.PasswordSecretID,
		})
	}
	if identity != nil {
		methods = append(methods, identity.Methods...)
	}
	return methods
}

func mergeRoute(base Route, override *Route) Route {
	if override == nil {
		return base
	}
	if len(override.ProxyJump) > 0 {
		base.ProxyJump = append([]string(nil), override.ProxyJump...)
	}
	if override.OutboundProxy != nil {
		proxy := *override.OutboundProxy
		base.OutboundProxy = &proxy
	}
	return base
}

func resolveForwards(hostForwardIDs []string, profiles []Profile, available map[string]Forward) []Forward {
	order := make([]string, 0, len(hostForwardIDs)+len(profiles))
	index := map[string]int{}
	for _, profile := range profiles {
		for _, id := range profile.ForwardIDs {
			if _, ok := index[id]; ok {
				continue
			}
			index[id] = len(order)
			order = append(order, id)
		}
	}
	for _, id := range hostForwardIDs {
		if pos, ok := index[id]; ok {
			order[pos] = ""
		}
		index[id] = len(order)
		order = append(order, id)
	}
	out := make([]Forward, 0, len(order))
	for _, id := range order {
		if id == "" {
			continue
		}
		forward, ok := available[id]
		if !ok {
			continue
		}
		out = append(out, forward)
	}
	return out
}

func cloneIdentity(in *Identity) *Identity {
	if in == nil {
		return nil
	}
	out := *in
	out.Methods = append([]AuthMethod(nil), in.Methods...)
	return &out
}
