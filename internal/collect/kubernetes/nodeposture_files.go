package kubernetes

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/nodeposture"
)

// nodeposture_files.go turns one node's file stats into the CIS file settings:
// node_file_<role>_mode (octal permission bits, the union over a directory's
// files) and node_file_<role>_owner ("user:group", every distinct owner joined
// with ","). The checks grade them; this file only normalises.
//
// A file the benchmark checks only "if it exists" (the kube-proxy kubeconfig,
// the kubelet config file, the CNI directory, super-admin.conf
// before v1.29) reports "absent" when it is not there. Any other absent file is
// unknown: it means the chart's paths do not match this distribution, and
// reading that as compliant would hide every file the reader failed to find.

// statRoles are the single-file roles and the key stem each feeds.
// super_admin_kubeconfig folds into admin_kubeconfig: CIS 1.1.13/1.1.14 cover
// both default administrative credential files.
var statRoles = map[string]string{
	"kubelet_service":               "kubelet_service",
	"kube_proxy_kubeconfig":         "kube_proxy_kubeconfig",
	"kubelet_kubeconfig":            "kubelet_kubeconfig",
	"client_ca":                     "client_ca",
	"kubelet_config":                "kubelet_config",
	"apiserver_manifest":            "apiserver_manifest",
	"controller_manager_manifest":   "controller_manager_manifest",
	"scheduler_manifest":            "scheduler_manifest",
	"etcd_manifest":                 "etcd_manifest",
	"etcd_data_dir":                 "etcd_data_dir",
	"admin_kubeconfig":              "admin_kubeconfig",
	"super_admin_kubeconfig":        "admin_kubeconfig",
	"scheduler_kubeconfig":          "scheduler_kubeconfig",
	"controller_manager_kubeconfig": "controller_manager_kubeconfig",
	"azure_json":                    "azure_json",
}

// optionalRoles may be absent without that being missing data.
// The kubelet service file is not among them: a unit the chart's path does not
// find means the path is wrong for this distribution, not that the kubelet has
// no unit.
var optionalRoles = map[string]bool{
	"kube_proxy_kubeconfig": true, "kubelet_config": true,
	"super_admin_kubeconfig": true, "cni_dir": true,
}

// absentValue marks a file the benchmark only checks when it exists.
const absentValue = "absent"

// fileAgg accumulates one key stem's observations on one node.
type fileAgg struct {
	mode         uint64
	owners       []string
	present      bool
	unknown      bool // nothing about the stem is known
	ownerUnknown bool // the mode is known, the owner's name is not
}

func (g *fileAgg) add(mode string, owner string) {
	m, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		g.unknown = true
		return
	}
	g.present = true
	g.mode |= m
	if owner == "" {
		g.ownerUnknown = true
	} else if !slices.Contains(g.owners, owner) {
		g.owners = append(g.owners, owner)
	}
}

func (g *fileAgg) write(out map[string]string, stem string) {
	modeKey, ownerKey := "node_file_"+stem+"_mode", "node_file_"+stem+"_owner"
	switch {
	case g.unknown:
	case !g.present:
		out[modeKey], out[ownerKey] = absentValue, absentValue
	default:
		out[modeKey] = fmt.Sprintf("%04o", g.mode)
		if !g.ownerUnknown {
			sort.Strings(g.owners)
			out[ownerKey] = strings.Join(g.owners, ",")
		}
	}
}

func fileSettings(files []nodeposture.File) map[string]string {
	users, groups := idNames(files, "host_passwd"), idNames(files, "host_group")
	aggs := map[string]*fileAgg{}
	agg := func(stem string) *fileAgg {
		if aggs[stem] == nil {
			aggs[stem] = &fileAgg{}
		}
		return aggs[stem]
	}
	for _, f := range files {
		if f.Role == "pki_dir" || f.Role == "cni_dir" {
			treeSettings(f, users, groups, agg)
			continue
		}
		stem, ok := statRoles[f.Role]
		if !ok {
			continue
		}
		g := agg(stem)
		switch {
		case f.Error != "":
			g.unknown = true
		case !f.Exists:
			if !optionalRoles[f.Role] {
				g.unknown = true
			}
		default:
			g.add(f.Mode, owner(f.UID, f.GID, users, groups, f.Role == "etcd_data_dir"))
		}
	}
	out := map[string]string{}
	for stem, g := range aggs {
		g.write(out, stem)
	}
	// The PKI tree is graded on its owner (1.1.19) and on certificate and key
	// modes (1.1.20, 1.1.21); the other halves of those stems are not controls.
	for _, k := range []string{"node_file_pki_mode", "node_file_pki_cert_owner", "node_file_pki_key_owner"} {
		delete(out, k)
	}
	return out
}

// treeSettings folds a directory role into its stems: the PKI tree into owner,
// certificate mode and key mode (CIS 1.1.19-1.1.21), the CNI directory into
// one mode and owner over its files (CIS 1.1.9/1.1.10).
func treeSettings(f nodeposture.File, users, groups map[uint32]string, agg func(string) *fileAgg) {
	stems := []string{"cni"}
	if f.Role == "pki_dir" {
		stems = []string{"pki", "pki_cert", "pki_key"}
	}
	switch {
	case f.Error != "":
		for _, s := range stems {
			agg(s).unknown = true
		}
		return
	case !f.Exists:
		for _, s := range stems {
			agg(s).unknown = !optionalRoles[f.Role] // optional: written as absent
		}
		return
	}
	if f.Role == "cni_dir" {
		g := agg("cni")
		g.present = true // an empty CNI directory holds nothing to fail
		for _, e := range f.Entries {
			uid, gid := e.UID, e.GID
			g.add(e.Mode, owner(&uid, &gid, users, groups, false))
		}
		return
	}
	// The PKI owner covers the directory itself as well as every file; the
	// mode stems cover only certificates and keys respectively.
	ownerAgg, certs, keys := agg("pki"), agg("pki_cert"), agg("pki_key")
	ownerAgg.add(f.Mode, owner(f.UID, f.GID, users, groups, false))
	certs.present, keys.present = true, true
	for _, e := range f.Entries {
		uid, gid := e.UID, e.GID
		o := owner(&uid, &gid, users, groups, false)
		ownerAgg.add("0", o)
		switch path.Ext(e.Path) {
		case ".crt":
			certs.add(e.Mode, o)
		case ".key":
			keys.add(e.Mode, o)
		}
	}
}

// owner renders uid:gid as names. uid/gid 0 is root everywhere; other ids use
// the node's passwd/group when the chart mounts them. strict demands names
// (the etcd data directory must be owned by etcd:etcd, which an id cannot
// prove), returning "" — unknown — when one does not resolve.
func owner(uid, gid *uint32, users, groups map[uint32]string, strict bool) string {
	if uid == nil || gid == nil {
		return ""
	}
	u, uok := idName(*uid, users)
	g, gok := idName(*gid, groups)
	if strict && (!uok || !gok) {
		return ""
	}
	return u + ":" + g
}

func idName(id uint32, names map[uint32]string) (string, bool) {
	if id == 0 {
		return "root", true
	}
	if n, ok := names[id]; ok {
		return n, true
	}
	return strconv.FormatUint(uint64(id), 10), false
}

// idNames parses a passwd- or group-format file: name:x:id:...
func idNames(files []nodeposture.File, role string) map[uint32]string {
	f, ok := findRole(files, role)
	if !ok || f.Error != "" {
		return nil
	}
	out := map[uint32]string{}
	for _, line := range strings.Split(f.Content, "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 || strings.HasPrefix(parts[0], "#") {
			continue
		}
		if id, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
			out[uint32(id)] = parts[0]
		}
	}
	return out
}
