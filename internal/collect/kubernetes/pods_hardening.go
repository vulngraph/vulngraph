package kubernetes

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// pods_hardening.go — the Pod Security Standard signals podAsset records beyond
// privilege/root/escalation: host namespaces and mounts, the full capability
// set, seccomp, AppArmor, root-filesystem writability, Secrets in environment
// variables and Windows HostProcess. Every one of them comes from the pod spec
// the collector already lists; nothing here makes an API call.
//
// The values are what the spec SAYS, aggregated across init and app
// containers (an init container runs on the same node, with the same service
// account, and is routinely the most privileged thing in the pod). List-valued
// keys are sorted and de-duplicated so the same spec always serialises the same
// way, and an empty list is the observation "none", never an unread field —
// the pod object was read in full or not at all.

// dangerousCapabilities are added capabilities that are a container escape or
// host compromise on their own: SYS_ADMIN (mount/namespace operations),
// SYS_MODULE (load a kernel module), SYS_RAWIO and DAC_READ_SEARCH (raw device
// and arbitrary file reads, the "shocker" escape), SYS_PTRACE (trace host
// processes once a PID namespace is shared), NET_ADMIN (rewrite node
// networking), BPF (load kernel programs) and ALL.
var dangerousCapabilities = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_MODULE": true, "SYS_RAWIO": true,
	"DAC_READ_SEARCH": true, "SYS_PTRACE": true, "NET_ADMIN": true, "BPF": true,
}

// normalizeCapability maps a capability to its kernel name without the CAP_
// prefix: container runtimes accept "CAP_SYS_ADMIN" and "sys_admin" as well as
// "SYS_ADMIN", so an exact-match list reading only the last spelling misses the
// other two.
func normalizeCapability(c corev1.Capability) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(string(c))), "CAP_")
}

// podHardeningSignals returns the metadata keys described above for one pod.
func podHardeningSignals(pod corev1.Pod) map[string]string {
	psc := pod.Spec.SecurityContext
	containers := podContainers(pod)

	added := map[string]bool{}
	secretRefs := map[string]bool{}
	hostPorts := map[string]bool{}
	var netRawRetained, seccompUnrestricted, appArmorUnconfined, writableRootFS, windowsHostProcess bool

	for _, c := range containers {
		csc := c.SecurityContext

		var drop, add []string
		if csc != nil && csc.Capabilities != nil {
			for _, cp := range csc.Capabilities.Add {
				n := normalizeCapability(cp)
				add = append(add, n)
				added[n] = true
			}
			for _, cp := range csc.Capabilities.Drop {
				drop = append(drop, normalizeCapability(cp))
			}
		}
		// NET_RAW is in the runtime's default set, so a container keeps it unless
		// it drops NET_RAW (or ALL) — and adding it back after a drop undoes that.
		dropped := slices.Contains(drop, "NET_RAW") || slices.Contains(drop, "ALL")
		if !dropped || slices.Contains(add, "NET_RAW") || slices.Contains(add, "ALL") {
			netRawRetained = true
		}

		// The container-level profile overrides the pod-level one. Unset means the
		// runtime default applies only when the kubelet runs with --seccomp-default,
		// which is node configuration Vulngraph cannot read, so unset is recorded as
		// unrestricted, as the benchmark audits it.
		profile := (*corev1.SeccompProfile)(nil)
		if psc != nil {
			profile = psc.SeccompProfile
		}
		if csc != nil && csc.SeccompProfile != nil {
			profile = csc.SeccompProfile
		}
		if profile == nil || (profile.Type != corev1.SeccompProfileTypeRuntimeDefault && profile.Type != corev1.SeccompProfileTypeLocalhost) {
			seccompUnrestricted = true
		}

		if containerAppArmorUnconfined(pod, c.Container) {
			appArmorUnconfined = true
		}

		if csc == nil || csc.ReadOnlyRootFilesystem == nil || !*csc.ReadOnlyRootFilesystem {
			writableRootFS = true
		}

		hostProcess := psc != nil && psc.WindowsOptions != nil && psc.WindowsOptions.HostProcess != nil && *psc.WindowsOptions.HostProcess
		if csc != nil && csc.WindowsOptions != nil && csc.WindowsOptions.HostProcess != nil {
			hostProcess = *csc.WindowsOptions.HostProcess
		}
		if hostProcess {
			windowsHostProcess = true
		}

		// Secret NAMES only, never values: the collector never reads a Secret.
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
				secretRefs[e.ValueFrom.SecretKeyRef.Name] = true
			}
		}
		for _, e := range c.EnvFrom {
			if e.SecretRef != nil {
				secretRefs[e.SecretRef.Name] = true
			}
		}

		for _, p := range c.Ports {
			if p.HostPort > 0 {
				hostPorts[strconv.Itoa(int(p.HostPort))] = true
			}
		}
	}

	hostPaths := map[string]bool{}
	for _, v := range pod.Spec.Volumes {
		if v.HostPath != nil {
			hostPaths[v.HostPath.Path] = true
		}
	}

	var dangerous []string
	for c := range added {
		if dangerousCapabilities[c] {
			dangerous = append(dangerous, c)
		}
	}
	slices.Sort(dangerous)

	return map[string]string{
		"host_ipc":               fmt.Sprintf("%t", pod.Spec.HostIPC),
		"host_path_volumes":      joinSet(hostPaths),
		"host_ports":             joinSet(hostPorts),
		"added_capabilities":     joinSet(added),
		"dangerous_capabilities": strings.Join(dangerous, ","),
		"net_raw_retained":       fmt.Sprintf("%t", netRawRetained),
		"seccomp_unrestricted":   fmt.Sprintf("%t", seccompUnrestricted),
		"apparmor_unconfined":    fmt.Sprintf("%t", appArmorUnconfined),
		"writable_root_fs":       fmt.Sprintf("%t", writableRootFS),
		"secret_env_refs":        joinSet(secretRefs),
		"windows_host_process":   fmt.Sprintf("%t", windowsHostProcess),
		"pod_os":                 podOS(pod, windowsHostProcess),
	}
}

// podOS is the operating system the pod declares it runs on: spec.os, else the
// kubernetes.io/os node selector, else "windows" for a HostProcess pod (which
// only exists on Windows). "" means the spec does not say, which in practice is
// Linux.
func podOS(pod corev1.Pod, hostProcess bool) string {
	switch {
	case pod.Spec.OS != nil:
		return string(pod.Spec.OS.Name)
	case pod.Spec.NodeSelector[corev1.LabelOSStable] != "":
		return pod.Spec.NodeSelector[corev1.LabelOSStable]
	case hostProcess:
		return string(corev1.Windows)
	}
	return ""
}

// containerAppArmorUnconfined reports whether a container explicitly opts out
// of AppArmor confinement, through the securityContext field (container over
// pod) or the beta annotation that predates it. An unset profile is the
// runtime's default confinement on a node that has AppArmor, so only an
// explicit Unconfined is a weakening the spec can be held to.
func containerAppArmorUnconfined(pod corev1.Pod, c corev1.Container) bool {
	var profile *corev1.AppArmorProfile
	if pod.Spec.SecurityContext != nil {
		profile = pod.Spec.SecurityContext.AppArmorProfile
	}
	if c.SecurityContext != nil && c.SecurityContext.AppArmorProfile != nil {
		profile = c.SecurityContext.AppArmorProfile
	}
	if profile != nil {
		return profile.Type == corev1.AppArmorProfileTypeUnconfined
	}
	return pod.Annotations[corev1.DeprecatedAppArmorBetaContainerAnnotationKeyPrefix+c.Name] == corev1.DeprecatedAppArmorBetaProfileNameUnconfined
}

// joinSet serialises a set as a sorted, comma-joined string.
func joinSet(set map[string]bool) string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	slices.Sort(out)
	return strings.Join(out, ",")
}

// resolveAutomount fills automount_sa_token for a pod whose spec leaves it to
// the ServiceAccount (the pod-level field, when set, always wins and podAsset
// has already recorded it). saAutomount maps a ServiceAccount name to its
// automountServiceAccountToken; listed is false when the namespace's
// ServiceAccount list failed, and then the key stays absent — the SA's setting
// was not read, and defaulting to "true" would invent a token mount.
func resolveAutomount(meta map[string]string, saAutomount map[string]*bool, listed bool) {
	if _, set := meta["automount_sa_token"]; set || !listed {
		return
	}
	sa := meta["service_account"]
	if sa == "" {
		sa = "default"
	}
	meta["automount_sa_token"] = fmt.Sprintf("%t", effectiveAutomount(saAutomount[sa]))
}

// effectiveAutomount is Kubernetes' reading of an automountServiceAccountToken
// field: unset means mount.
func effectiveAutomount(v *bool) bool { return v == nil || *v }
