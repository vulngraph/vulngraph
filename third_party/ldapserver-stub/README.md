# ldapserver-stub

An inert, API-compatible stand-in for `github.com/projectdiscovery/ldapserver`,
substituted by a `replace` directive in the root `go.mod`.

**Why.** The upstream module is GPL-2.0. It reaches this project only because
nuclei's `pkg/output` imports `interactsh/pkg/server` for the
`server.Interaction` struct, which compiles in interactsh's LDAP *callback
server*. Vulngraph embeds nuclei as a scan engine and never runs an interactsh
server, so that listener is dead code here — but linking it would put GPL-2.0
code into every binary and container image of an MIT project.

**What.** Written from scratch against the call sites in
`interactsh/pkg/server/ldap_server.go` (MIT); it contains no code from the GPL
module. Every operation is a no-op, and `Server.ListenAndServe` always returns
`ErrDisabled`, so an attempt to start the LDAP listener fails loudly. Request
and response types come from `github.com/lor00x/goldap` (MIT).

**Verify.**

```sh
go version -m bin/graph | grep -A1 ldapserver   # => ./third_party/ldapserver-stub
go test ./internal/scanner/nuclei -run TestGPLLdapserverIsReplaced
```

If an interactsh upgrade changes the API it calls, the build fails at compile
time — extend this stub to match; never drop the `replace`.

License: MIT (this stand-in is under its own `LICENSE`, not the repository's).
