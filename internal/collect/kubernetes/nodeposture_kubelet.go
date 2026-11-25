package kubernetes

import (
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	utilyaml "k8s.io/apimachinery/pkg/util/yaml"

	"github.com/vulngraph/vulngraph/internal/nodeposture"
)

// nodeposture_kubelet.go derives one node's EFFECTIVE kubelet settings from the
// reader's report: the KubeletConfiguration file (role kubelet_config) with
// command-line flags layered on top, as the kubelet itself applies them. Flags
// come from every file the chart names as a flag source — kubeadm's
// kubeadm-flags.env, /etc/default/kubelet, the systemd unit or drop-in, EKS's
// nodeadm environment (roles kubelet_service and kubelet_flags*).
//
// Defaults are the KubeletConfiguration v1beta1 defaults (v1.30), which apply
// whenever the kubelet runs from a config file — every supported distribution
// does. They differ from the bare flag defaults: anonymous auth is off, the
// read-only port is 0 and authorization is Webhook.
//
// The kubelet's real command line is not read: that needs hostPID. A flag set
// somewhere other than the configured flag sources is therefore not seen; the
// chart lists each distribution's sources (ADR 094).

// kubeletConfig is the subset of KubeletConfiguration the CIS controls read.
// Pointers distinguish "unset" from the zero value.
type kubeletConfig struct {
	Authentication struct {
		Anonymous struct {
			Enabled *bool `json:"enabled"`
		} `json:"anonymous"`
		X509 struct {
			ClientCAFile string `json:"clientCAFile"`
		} `json:"x509"`
	} `json:"authentication"`
	Authorization struct {
		Mode string `json:"mode"`
	} `json:"authorization"`
	ReadOnlyPort                   *int32          `json:"readOnlyPort"`
	StreamingConnectionIdleTimeout *string         `json:"streamingConnectionIdleTimeout"`
	MakeIPTablesUtilChains         *bool           `json:"makeIPTablesUtilChains"`
	TLSCertFile                    string          `json:"tlsCertFile"`
	TLSPrivateKeyFile              string          `json:"tlsPrivateKeyFile"`
	RotateCertificates             *bool           `json:"rotateCertificates"`
	ServerTLSBootstrap             *bool           `json:"serverTLSBootstrap"`
	FeatureGates                   map[string]bool `json:"featureGates"`
	TLSCipherSuites                []string        `json:"tlsCipherSuites"`
	PodPidsLimit                   *int64          `json:"podPidsLimit"`
	SeccompDefault                 *bool           `json:"seccompDefault"`
}

// kubeletSettings returns the node's kubelet_* settings, or nothing when the
// configuration file was not read: without it every value would be a guess.
func kubeletSettings(files []nodeposture.File) map[string]string {
	out := map[string]string{}
	cfgFile, ok := findRole(files, "kubelet_config")
	if !ok || !cfgFile.Exists || cfgFile.Error != "" || cfgFile.Truncated {
		return out
	}
	flags, ok := kubeletFlags(files)
	if !ok {
		return out
	}
	js, ok := effectiveKubeletConfig(cfgFile.Content, flags["config-dir"], files)
	if !ok {
		return out
	}
	var cfg kubeletConfig
	if err := json.Unmarshal(js, &cfg); err != nil {
		return out
	}
	r := settingReader{flags: flags, out: out}

	kubeletBool(r, "kubelet_anonymous_auth", "anonymous-auth", cfg.Authentication.Anonymous.Enabled, false)
	r.out["kubelet_authorization_mode"] = firstNonEmpty(flags["authorization-mode"], cfg.Authorization.Mode, "Webhook")
	r.out["kubelet_client_ca_set"] = strconv.FormatBool(firstNonEmpty(flags["client-ca-file"], cfg.Authentication.X509.ClientCAFile) != "")
	if v, ok := flags["read-only-port"]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			r.out["kubelet_read_only_port"] = strconv.Itoa(n)
		}
	} else if cfg.ReadOnlyPort != nil {
		r.out["kubelet_read_only_port"] = strconv.Itoa(int(*cfg.ReadOnlyPort))
	} else {
		r.out["kubelet_read_only_port"] = "0"
	}
	if d, ok := streamingIdleTimeout(flags, cfg); ok {
		r.out["kubelet_streaming_idle_timeout"] = d.String()
	}
	kubeletBool(r, "kubelet_make_iptables_util_chains", "make-iptables-util-chains", cfg.MakeIPTablesUtilChains, true)
	r.out["kubelet_hostname_override_set"] = strconv.FormatBool(flags["hostname-override"] != "")
	r.out["kubelet_tls_cert_set"] = strconv.FormatBool(
		firstNonEmpty(flags["tls-cert-file"], cfg.TLSCertFile) != "" && firstNonEmpty(flags["tls-private-key-file"], cfg.TLSPrivateKeyFile) != "")
	// CIS 4.2.10 fails only an explicit false, so "unset" is kept distinct.
	switch v, ok := flags["rotate-certificates"]; {
	case ok:
		if b, err := strconv.ParseBool(v); err == nil {
			r.out["kubelet_rotate_certificates"] = strconv.FormatBool(b)
		}
	case cfg.RotateCertificates != nil:
		r.out["kubelet_rotate_certificates"] = strconv.FormatBool(*cfg.RotateCertificates)
	default:
		r.out["kubelet_rotate_certificates"] = "unset"
	}
	r.out["kubelet_rotate_server_certificates"] = strconv.FormatBool(!serverCertRotationOff(flags, cfg))
	r.out["kubelet_tls_cipher_suites"] = firstNonEmpty(flags["tls-cipher-suites"], strings.Join(cfg.TLSCipherSuites, ","))
	switch v, ok := flags["pod-max-pids"]; {
	case ok:
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			r.out["kubelet_pod_pids_limit"] = strconv.FormatInt(n, 10)
		}
	case cfg.PodPidsLimit != nil:
		r.out["kubelet_pod_pids_limit"] = strconv.FormatInt(*cfg.PodPidsLimit, 10)
	default:
		r.out["kubelet_pod_pids_limit"] = "-1"
	}
	kubeletBool(r, "kubelet_seccomp_default", "seccomp-default", cfg.SeccompDefault, false)
	return out
}

// effectiveKubeletConfig returns the config file as JSON with the
// --config-dir drop-ins applied. The kubelet (1.30, KEP-3983) reads only
// *.conf files in that directory, in name order, each merged over the result
// so far (objects field by field, everything else replaced). With --config-dir
// set, the drop-ins must have been read (role kubelet_config_dropins) or the
// configuration is unknown: any field could be overridden there.
func effectiveKubeletConfig(content, configDir string, files []nodeposture.File) ([]byte, bool) {
	js, err := utilyaml.ToJSON([]byte(content))
	if err != nil {
		return nil, false
	}
	if configDir == "" {
		return js, true
	}
	dir, ok := findRole(files, "kubelet_config_dropins")
	if !ok || dir.Error != "" {
		return nil, false
	}
	var base map[string]any
	if err := json.Unmarshal(js, &base); err != nil {
		return nil, false
	}
	entries := slices.Clone(dir.Entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, e := range entries {
		if !strings.HasSuffix(e.Path, ".conf") {
			continue
		}
		if e.Truncated {
			return nil, false
		}
		djs, err := utilyaml.ToJSON([]byte(e.Content))
		if err != nil {
			return nil, false
		}
		var drop map[string]any
		if err := json.Unmarshal(djs, &drop); err != nil {
			return nil, false
		}
		base = mergeJSON(base, drop)
	}
	out, err := json.Marshal(base)
	return out, err == nil
}

// mergeJSON merges over onto base: nested objects field by field, any other
// value replaced.
func mergeJSON(base, over map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for k, v := range over {
		if vm, ok := v.(map[string]any); ok {
			if bm, ok := base[k].(map[string]any); ok {
				base[k] = mergeJSON(bm, vm)
				continue
			}
		}
		base[k] = v
	}
	return base
}

// defaultStreamingIdleTimeout is KubeletConfiguration's default.
const defaultStreamingIdleTimeout = 4 * time.Hour

// streamingIdleTimeout resolves streamingConnectionIdleTimeout. A zero in the
// config FILE is defaulted to 4h by the kubelet (kubeadm writes "0s" there for
// every unset duration); a zero FLAG is applied after defaulting and sticks.
func streamingIdleTimeout(flags map[string]string, cfg kubeletConfig) (time.Duration, bool) {
	if v, ok := flags["streaming-connection-idle-timeout"]; ok {
		d, err := time.ParseDuration(v)
		return d, err == nil
	}
	if cfg.StreamingConnectionIdleTimeout == nil {
		return defaultStreamingIdleTimeout, true
	}
	d, err := time.ParseDuration(*cfg.StreamingConnectionIdleTimeout)
	if err != nil {
		return 0, false
	}
	if d == 0 {
		return defaultStreamingIdleTimeout, true
	}
	return d, true
}

// kubeletBool resolves a boolean: flag, else config field, else default. An
// unparseable flag leaves the key unknown.
func kubeletBool(r settingReader, key, flag string, cfg *bool, def bool) {
	if _, ok := r.flags[flag]; ok {
		r.boolean(key, flag, def)
		return
	}
	if cfg != nil {
		r.out[key] = strconv.FormatBool(*cfg)
		return
	}
	r.out[key] = strconv.FormatBool(def)
}

// serverCertRotationOff is CIS 4.2.11's failing state: the
// RotateKubeletServerCertificate gate explicitly false, unless the kubelet
// bootstraps its serving certificate anyway (serverTLSBootstrap or
// --rotate-server-certificates).
func serverCertRotationOff(flags map[string]string, cfg kubeletConfig) bool {
	if b, err := strconv.ParseBool(flags["rotate-server-certificates"]); err == nil && b {
		return false
	}
	if cfg.ServerTLSBootstrap != nil && *cfg.ServerTLSBootstrap {
		return false
	}
	gate := featureGate(flags["feature-gates"], "RotateKubeletServerCertificate")
	if gate == "" {
		if v, ok := cfg.FeatureGates["RotateKubeletServerCertificate"]; ok {
			gate = strconv.FormatBool(v)
		}
	}
	return gate == "false"
}

// kubeletFlags collects --flag=value tokens from every flag-source role, in
// report order (later wins, as on a command line). ok=false when a source
// exists but could not be read: a missing flag might be in it.
func kubeletFlags(files []nodeposture.File) (map[string]string, bool) {
	flags := map[string]string{}
	for _, f := range files {
		if f.Role != "kubelet_service" && !strings.HasPrefix(f.Role, "kubelet_flags") {
			continue
		}
		if !f.Exists {
			continue // an optional EnvironmentFile that is not there
		}
		if f.Error != "" || f.Truncated {
			return nil, false
		}
		for _, line := range strings.Split(f.Content, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, tok := range strings.Fields(strings.NewReplacer(`"`, " ", `'`, " ").Replace(line)) {
				i := strings.Index(tok, "--")
				if i < 0 || (i > 0 && tok[i-1] != '=') {
					continue
				}
				name, value, eq := strings.Cut(tok[i+2:], "=")
				if name == "" {
					continue
				}
				if !eq {
					value = "true"
				}
				flags[name] = value
			}
		}
	}
	return flags, true
}

func findRole(files []nodeposture.File, role string) (nodeposture.File, bool) {
	for _, f := range files {
		if f.Role == role {
			return f, true
		}
	}
	return nodeposture.File{}, false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
