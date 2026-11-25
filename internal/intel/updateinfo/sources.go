package updateinfo

import "github.com/vulngraph/vulngraph/internal/distro"

// Hosts the feeds reach, for the egress allowlist (docs/configuration.md).
const (
	AmazonLinuxHost = "cdn.amazonlinux.com"
	OracleLinuxHost = "yum.oracle.com"
)

// oracleArchs are both read for Oracle Linux: each architecture's repository
// lists only its own builds, and Ampere hosts install aarch64 ones.
var oracleArchs = []string{"x86_64", "aarch64"}

// al2KernelLines are the Amazon Linux 2 kernel extras topics
// (amazon-linux-extras install kernel-5.10). Each is its own repository with
// its own ALAS2KERNEL-<line> advisories; a host on one runs kernel, perf and
// bpftool at that line's version, which the core repository's 4.14 errata do
// not cover. Verified live 2026-10-09 (kernel-6.1 is not published for AL2).
var al2KernelLines = []string{"5.4", "5.10", "5.15"}

// ALASSources are the Amazon Linux releases with a live core repository.
// Amazon Linux 1 is absent: its repository is frozen since end of life
// (2023-12-31), and its hosts are stamped eol_distro instead.
//
// Only x86_64 repositories are read: Amazon's updateinfo lists every
// architecture's packages, and the aarch64 repository's file is byte-identical
// (same repomd checksum). Amazon Linux 2 extras topics other than the kernel
// lines (nginx1, php8.x, …) publish their own ALAS2<TOPIC> advisories in
// per-topic repositories and are a documented gap.
func ALASSources() []Source {
	al2 := Source{Feed: distro.SourceALAS, Ecosystem: "Amazon Linux:2",
		Repos:     []Repo{{MirrorList: "https://" + AmazonLinuxHost + "/2/core/latest/x86_64/mirror.list"}},
		URLPrefix: "https://alas.aws.amazon.com/AL2/", URLSuffix: ".html"}
	for _, line := range al2KernelLines {
		al2.Repos = append(al2.Repos, Repo{
			MirrorList: "https://" + AmazonLinuxHost + "/2/extras/kernel-" + line + "/latest/x86_64/mirror.list",
			Stream:     line,
		})
	}
	return []Source{
		al2,
		{Feed: distro.SourceALAS, Ecosystem: "Amazon Linux:2023",
			Repos:     []Repo{{MirrorList: "https://" + AmazonLinuxHost + "/al2023/core/mirrors/latest/x86_64/mirror.list"}},
			URLPrefix: "https://alas.aws.amazon.com/AL2023/", URLSuffix: ".html"},
	}
}

// uekChannel is one Unbreakable Enterprise Kernel channel of a release: its
// repository name, its kernel line and the architectures Oracle publishes it
// for (an absent architecture is a 404, and one unreadable repository fails
// the whole release).
type uekChannel struct {
	name, line string
	archs      []string
}

// ELSASources are the Oracle Linux releases on the public yum server. Oracle
// Linux 7 has one "latest" repository; 8 and later split BaseOS and AppStream,
// each with its own updateinfo. The UEK channels carry the kernel-uek errata
// and are read as kernel-line streams. The channel × architecture matrix was
// verified against yum.oracle.com 2026-10-09.
func ELSASources() []Source {
	const root = "https://" + OracleLinuxHost + "/repo/OracleLinux/"
	x86 := []string{"x86_64"}
	release := func(major string, uek []uekChannel, paths ...string) Source {
		s := Source{Feed: distro.SourceELSA, Ecosystem: "Oracle Linux:" + major,
			URLPrefix: "https://linux.oracle.com/errata/", URLSuffix: ".html"}
		for _, a := range oracleArchs {
			for _, p := range paths {
				s.Repos = append(s.Repos, Repo{BaseURL: root + "OL" + major + "/" + p + a + "/"})
			}
		}
		for _, ch := range uek {
			for _, a := range ch.archs {
				s.Repos = append(s.Repos, Repo{BaseURL: root + "OL" + major + "/" + ch.name + "/" + a + "/", Stream: ch.line})
			}
		}
		return s
	}
	return []Source{
		release("7", []uekChannel{{"UEKR4", "4.1", x86}, {"UEKR5", "4.14", x86}, {"UEKR6", "5.4", oracleArchs}}, "latest/"),
		release("8", []uekChannel{{"UEKR6", "5.4", x86}, {"UEKR7", "5.15", oracleArchs}}, "baseos/latest/", "appstream/"),
		release("9", []uekChannel{{"UEKR7", "5.15", oracleArchs}, {"UEKR8", "6.12", oracleArchs}}, "baseos/latest/", "appstream/"),
		release("10", []uekChannel{{"UEKR8", "6.12", oracleArchs}}, "baseos/latest/", "appstream/"),
	}
}
