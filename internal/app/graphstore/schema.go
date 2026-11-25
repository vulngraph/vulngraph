package graphstore

import (
	"fmt"
	"strings"
	"time"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
)

// ─── Schema DDL ───────────────────────────────────────────────────────────────
//
// This file is purely the Ladybug DDL + UNWIND insert templates; repo.go keeps
// the connection lifecycle and bulk-sync logic that uses them.

// dropDDL drops all rel tables (before node tables — Ladybug constraint) then node
// tables. Used during schema upgrades so column changes take effect. On a fresh
// database the IF EXISTS clauses make every statement a no-op.
const dropDDL = `
DROP TABLE IF EXISTS AssignedTo;
DROP TABLE IF EXISTS GrantsAccessTo;
DROP TABLE IF EXISTS GrantsAdmin;
DROP TABLE IF EXISTS DefinedInK8sWorkload;
DROP TABLE IF EXISTS DefinedInAsset;
DROP TABLE IF EXISTS DefinedInIamRole;
DROP TABLE IF EXISTS PermissionSet;
DROP TABLE IF EXISTS ` + "`Group`" + `;
DROP TABLE IF EXISTS RunsIn;
DROP TABLE IF EXISTS DeployedBy;
DROP TABLE IF EXISTS CanEscalateTo;
DROP TABLE IF EXISTS Accesses;
DROP TABLE IF EXISTS RunsPackage;
DROP TABLE IF EXISTS ExecutesAs;
DROP TABLE IF EXISTS ExecutesAsK8sWorkload;
DROP TABLE IF EXISTS ExecutesAsK8sServiceAccount;
DROP TABLE IF EXISTS MemberOf;
DROP TABLE IF EXISTS MemberOfGroup;
DROP TABLE IF EXISTS AccessesK8sWorkload;
DROP TABLE IF EXISTS ExposedToInternet;
DROP TABLE IF EXISTS ExposedToInternetK8sWorkload;
DROP TABLE IF EXISTS HasRole;
DROP TABLE IF EXISTS ConnectedViaSG;
DROP TABLE IF EXISTS AllowsFrom;
DROP TABLE IF EXISTS FederatedAccess;
DROP TABLE IF EXISTS FederatedAccessK8sWorkload;
DROP TABLE IF EXISTS FederatedAccessAsset;
DROP TABLE IF EXISTS OwnsAsset;
DROP TABLE IF EXISTS PeeredWith;
DROP TABLE IF EXISTS Binds;
DROP TABLE IF EXISTS BindsK8sWorkload;
DROP TABLE IF EXISTS AccessesSecret;
DROP TABLE IF EXISTS InVPC;
DROP TABLE IF EXISTS DependsOn;
DROP TABLE IF EXISTS DeploysTo;
DROP TABLE IF EXISTS DeploysToService;
DROP TABLE IF EXISTS CanAssume;
DROP TABLE IF EXISTS ProtectedBy;
DROP TABLE IF EXISTS DnsPointsTo;
DROP TABLE IF EXISTS Owns;
DROP TABLE IF EXISTS HasPolicy;
DROP TABLE IF EXISTS InSubnet;
DROP TABLE IF EXISTS MemberOfZone;
DROP TABLE IF EXISTS AllowsAction;
DROP TABLE IF EXISTS ContainsData;
DROP TABLE IF EXISTS RunsImage;
DROP TABLE IF EXISTS RunsImageAsset;
DROP TABLE IF EXISTS RunsContainer;
DROP TABLE IF EXISTS Edge;
DROP TABLE IF EXISTS Asset;
DROP TABLE IF EXISTS Package;
DROP TABLE IF EXISTS Repo;
DROP TABLE IF EXISTS IamRole;
DROP TABLE IF EXISTS K8sWorkload;
DROP TABLE IF EXISTS Subnet;
DROP TABLE IF EXISTS DataClass;
DROP TABLE IF EXISTS _SchemaMeta;
`

// Signal columns (exposed/has_kev/exploitable/toxic_combo/max_score/privesc_count)
// are INT32, not BOOL: the bool flags are stored as 0/1 and queried as
// `n.has_kev = 1`. They stay INT32 for compatibility — saved user queries and the
// named queries compare with `= 1`.
const schemaDDL = `
CREATE NODE TABLE IF NOT EXISTS Asset(
    id STRING, name STRING, type STRING, provider STRING,
    region STRING, account_id STRING, score INT32,
    exposed INT32, has_kev INT32, exploitable INT32, toxic_combo INT32,
    max_score INT32, privesc_count INT32, internet_hops INT32,
    encrypted INT32, public INT32, public_tier INT32,
    expires_at STRING, days_until_expiry INT32, expiring_soon INT32,
    PRIMARY KEY(id)
);
CREATE NODE TABLE IF NOT EXISTS Package(
    id STRING, name STRING, ecosystem STRING, version STRING,
    score INT32, has_kev INT32, exploitable INT32,
    cve_id STRING, epss_score DOUBLE,
    PRIMARY KEY(id)
);
CREATE NODE TABLE IF NOT EXISTS Repo(
    id STRING, name STRING, provider STRING,
    PRIMARY KEY(id)
);
CREATE NODE TABLE IF NOT EXISTS IamRole(
    id STRING, name STRING, provider STRING, account_id STRING,
    score INT32, type STRING, region STRING,
    exposed INT32, has_kev INT32, exploitable INT32, toxic_combo INT32,
    max_score INT32, privesc_count INT32, internet_hops INT32,
    trust_entry STRING,
    PRIMARY KEY(id)
);
CREATE NODE TABLE IF NOT EXISTS K8sWorkload(
    id STRING, name STRING, type STRING, provider STRING,
    region STRING, account_id STRING, score INT32,
    exposed INT32, has_kev INT32, exploitable INT32, toxic_combo INT32,
    max_score INT32, privesc_count INT32, internet_hops INT32,
    PRIMARY KEY(id)
);
CREATE NODE TABLE IF NOT EXISTS Subnet(
    id STRING, name STRING, type STRING, provider STRING,
    region STRING, account_id STRING, score INT32,
    PRIMARY KEY(id)
);
CREATE NODE TABLE IF NOT EXISTS _SchemaMeta(id STRING, version STRING, built_at STRING, PRIMARY KEY(id));
CREATE NODE TABLE IF NOT EXISTS CloudAccount(id STRING, name STRING, provider STRING, account_id STRING, PRIMARY KEY(id));
CREATE NODE TABLE IF NOT EXISTS DNSZone(id STRING, name STRING, provider STRING, zone_id STRING, PRIMARY KEY(id));
CREATE NODE TABLE IF NOT EXISTS IamPolicy(id STRING, name STRING, account_id STRING, PRIMARY KEY(id));
CREATE NODE TABLE IF NOT EXISTS DataClass(id STRING, classification STRING, PRIMARY KEY(id));
CREATE NODE TABLE IF NOT EXISTS ` + "`Group`" + `(id STRING, name STRING, provider STRING, PRIMARY KEY(id));
CREATE NODE TABLE IF NOT EXISTS PermissionSet(id STRING, name STRING, provider STRING, account_id STRING, grants_admin INT32, PRIMARY KEY(id));

CREATE REL TABLE IF NOT EXISTS RunsIn(FROM Package TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS DeployedBy(FROM Asset TO Repo, via STRING);
CREATE REL TABLE IF NOT EXISTS CanEscalateTo(FROM IamRole TO IamRole, via STRING);
CREATE REL TABLE IF NOT EXISTS Accesses(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS RunsPackage(FROM Asset TO Package, via STRING);
CREATE REL TABLE IF NOT EXISTS ExecutesAs(FROM Asset TO IamRole, via STRING);
CREATE REL TABLE IF NOT EXISTS ExecutesAsK8sWorkload(FROM K8sWorkload TO IamRole, via STRING);
CREATE REL TABLE IF NOT EXISTS ExecutesAsK8sServiceAccount(FROM K8sWorkload TO K8sWorkload, via STRING);
CREATE REL TABLE IF NOT EXISTS AccessesK8sWorkload(FROM Asset TO K8sWorkload, via STRING);
CREATE REL TABLE IF NOT EXISTS ExposedToInternet(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS ExposedToInternetK8sWorkload(FROM K8sWorkload TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS HasRole(FROM Asset TO IamRole, via STRING);
CREATE REL TABLE IF NOT EXISTS ConnectedViaSG(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS AllowsFrom(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS PeeredWith(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS DeploysTo(FROM Repo TO K8sWorkload, confidence STRING);
CREATE REL TABLE IF NOT EXISTS DeploysToService(FROM Repo TO Asset, confidence STRING);
CREATE REL TABLE IF NOT EXISTS DependsOn(FROM Repo TO Package, via STRING);
CREATE REL TABLE IF NOT EXISTS InVPC(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS Binds(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS BindsK8sWorkload(FROM K8sWorkload TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS AccessesSecret(FROM IamRole TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS CanAssume(FROM IamRole TO IamRole, via STRING);
CREATE REL TABLE IF NOT EXISTS ProtectedBy(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS DnsPointsTo(FROM Asset TO Asset, matched STRING);
CREATE REL TABLE IF NOT EXISTS FederatedAccess(FROM Repo TO IamRole, trust_type STRING, subject STRING, provenance STRING, confidence STRING, workflow_path STRING);
CREATE REL TABLE IF NOT EXISTS FederatedAccessK8sWorkload(FROM K8sWorkload TO IamRole, trust_type STRING, subject STRING, provenance STRING, confidence STRING, workflow_path STRING);
CREATE REL TABLE IF NOT EXISTS FederatedAccessAsset(FROM Asset TO IamRole, trust_type STRING, subject STRING, provenance STRING, confidence STRING, workflow_path STRING);
CREATE REL TABLE IF NOT EXISTS Edge(FROM Asset TO Asset, edge_type STRING, via STRING);
CREATE REL TABLE IF NOT EXISTS Owns(FROM CloudAccount TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS OwnsAsset(FROM Asset TO Repo, via STRING);
CREATE REL TABLE IF NOT EXISTS HasPolicy(FROM IamRole TO IamPolicy, via STRING);
CREATE REL TABLE IF NOT EXISTS AllowsAction(FROM IamRole TO IamPolicy, category STRING, policy_name STRING);
CREATE REL TABLE IF NOT EXISTS InSubnet(FROM Asset TO Subnet, via STRING);
CREATE REL TABLE IF NOT EXISTS MemberOfZone(FROM Asset TO DNSZone, via STRING);
CREATE REL TABLE IF NOT EXISTS RunsImage(FROM K8sWorkload TO Asset, image_ref STRING);
CREATE REL TABLE IF NOT EXISTS RunsImageAsset(FROM Asset TO Asset, image_ref STRING);
CREATE REL TABLE IF NOT EXISTS RunsContainer(FROM Asset TO Asset, via STRING);
CREATE REL TABLE IF NOT EXISTS ContainsData(FROM Asset TO DataClass, classification STRING, confidence STRING);
CREATE REL TABLE IF NOT EXISTS MemberOf(FROM Asset TO ` + "`Group`" + `, via STRING);
CREATE REL TABLE IF NOT EXISTS MemberOfGroup(FROM ` + "`Group`" + ` TO ` + "`Group`" + `, via STRING);
CREATE REL TABLE IF NOT EXISTS AssignedTo(FROM ` + "`Group`" + ` TO PermissionSet, confidence STRING, provenance STRING);
CREATE REL TABLE IF NOT EXISTS GrantsAccessTo(FROM PermissionSet TO CloudAccount, confidence STRING, provenance STRING);
CREATE REL TABLE IF NOT EXISTS GrantsAdmin(FROM PermissionSet TO CloudAccount, confidence STRING, provenance STRING);
CREATE REL TABLE IF NOT EXISTS DefinedInK8sWorkload(FROM K8sWorkload TO Repo, confidence STRING, provenance STRING, path STRING);
CREATE REL TABLE IF NOT EXISTS DefinedInAsset(FROM Asset TO Repo, confidence STRING, provenance STRING, path STRING);
CREATE REL TABLE IF NOT EXISTS DefinedInIamRole(FROM IamRole TO Repo, confidence STRING, provenance STRING);
`

func applySchema(conn *ladybug.Connection, version string) error {
	// Drop all tables before recreating — ensures column changes (e.g. new IamRole
	// fields) take effect. IF EXISTS makes this a no-op on a fresh database.
	for _, stmt := range splitDDL(dropDDL) {
		res, err := conn.Query(stmt)
		if err != nil {
			return fmt.Errorf("applySchema drop %s: %w", stmt[:minLen(40, len(stmt))], err)
		}
		res.Close()
	}
	for _, stmt := range splitDDL(schemaDDL) {
		res, err := conn.Query(stmt)
		if err != nil {
			return fmt.Errorf("applySchema %s: %w", stmt[:minLen(40, len(stmt))], err)
		}
		res.Close()
	}
	res, err := conn.Query(fmt.Sprintf(
		`CREATE (:_SchemaMeta {id: 'schema', version: '%s', built_at: '%s'})`,
		version, time.Now().UTC().Format(time.RFC3339),
	))
	if err != nil {
		return fmt.Errorf("applySchema: version insert: %w", err)
	}
	res.Close()
	return nil
}

// cypherReservedLabels are node/rel table names that collide with a Ladybug Cypher
// keyword and must be backtick-quoted anywhere they appear as a bare identifier —
// CREATE TABLE, MATCH, and COPY all reject it unescaped. "Group" collides with
// GROUP BY. Every static DDL/UNWIND string literal referencing Group is
// hand-escaped inline; quoteLabel covers the dynamically-built queries
// (copyFrom, neighbors).
var cypherReservedLabels = map[string]bool{"Group": true}

// quoteLabel backtick-quotes a node/rel table name if it collides with a Cypher
// keyword (see cypherReservedLabels); otherwise it is returned unchanged.
func quoteLabel(label string) string {
	if cypherReservedLabels[label] {
		return "`" + label + "`"
	}
	return label
}

func splitDDL(ddl string) []string {
	var stmts []string
	for s := range strings.SplitSeq(ddl, ";") {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "--") {
			continue
		}
		stmts = append(stmts, s)
	}
	return stmts
}

// ─── Bulk sync insert templates ────────────────────────────────────────────────

// unwindBatchSize is the max rows per UNWIND execution. Ladybug holds the full
// list in memory during execution; 5k rows keeps peak RSS low while still
// eliminating per-row CGO overhead (vs one Prepare per row).
const unwindBatchSize = 5000

// nodeUnwindQ is the UNWIND CREATE template per node label.
// All field names match the schema DDL columns exactly.
var nodeUnwindQ = map[string]string{
	NodeAsset:       `UNWIND $rows AS r CREATE (:Asset {id: r.id, name: r.name, type: r.type, provider: r.provider, region: r.region, account_id: r.account_id, score: r.score, exposed: r.exposed, has_kev: r.has_kev, exploitable: r.exploitable, toxic_combo: r.toxic_combo, max_score: r.max_score, privesc_count: r.privesc_count, internet_hops: r.internet_hops, encrypted: r.encrypted, public: r.public, public_tier: r.public_tier, expires_at: r.expires_at, days_until_expiry: r.days_until_expiry, expiring_soon: r.expiring_soon})`,
	NodeIamRole:     `UNWIND $rows AS r CREATE (:IamRole {id: r.id, name: r.name, provider: r.provider, account_id: r.account_id, score: r.score, type: r.type, region: r.region, exposed: r.exposed, has_kev: r.has_kev, exploitable: r.exploitable, toxic_combo: r.toxic_combo, max_score: r.max_score, privesc_count: r.privesc_count, internet_hops: r.internet_hops, trust_entry: r.trust_entry})`,
	NodeRepo:        `UNWIND $rows AS r CREATE (:Repo {id: r.id, name: r.name, provider: r.provider})`,
	NodePackage:     `UNWIND $rows AS r CREATE (:Package {id: r.id, name: r.name, ecosystem: r.ecosystem, version: r.version, score: r.score, has_kev: r.has_kev, exploitable: r.exploitable, cve_id: r.cve_id, epss_score: r.epss_score})`,
	NodeK8sWorkload: `UNWIND $rows AS r CREATE (:K8sWorkload {id: r.id, name: r.name, type: r.type, provider: r.provider, region: r.region, account_id: r.account_id, score: r.score, exposed: r.exposed, has_kev: r.has_kev, exploitable: r.exploitable, toxic_combo: r.toxic_combo, max_score: r.max_score, privesc_count: r.privesc_count, internet_hops: r.internet_hops})`,
	NodeSubnet:      `UNWIND $rows AS r CREATE (:Subnet {id: r.id, name: r.name, type: r.type, provider: r.provider, region: r.region, account_id: r.account_id, score: r.score})`,
	NodeDataClass:   `UNWIND $rows AS r CREATE (:DataClass {id: r.id, classification: r.classification})`,
	// NodeCloudAccount must stay wired here — Owns edges resolve their source
	// node through it, and GrantsAccessTo/GrantsAdmin target CloudAccount, so an
	// unwired label would drop those edges at the COPY endpoint pre-filter.
	NodeCloudAccount: `UNWIND $rows AS r CREATE (:CloudAccount {id: r.id, name: r.name, provider: r.provider, account_id: r.account_id})`,
	// NodeSSOGroup is "Group" — a Ladybug Cypher keyword (GROUP BY) the parser
	// rejects unescaped as a bare identifier. Every reference backtick-quotes it.
	NodeSSOGroup:   "UNWIND $rows AS r CREATE (:`Group` {id: r.id, name: r.name, provider: r.provider})",
	NodeSSOPermSet: `UNWIND $rows AS r CREATE (:PermissionSet {id: r.id, name: r.name, provider: r.provider, account_id: r.account_id, grants_admin: r.grants_admin})`,
}

// edgeUnwindQ is the UNWIND MATCH+CREATE template per rel table.
// MATCH inside UNWIND skips silently when src/dst nodes are absent — correct
// behaviour since edge datasets may reference nodes not in the Ladybug graph.
var edgeUnwindQ = map[string]string{
	"ExposedToInternet":            `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:ExposedToInternet {via: r.via}]->(d)`,
	"ExposedToInternetK8sWorkload": `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:ExposedToInternetK8sWorkload {via: r.via}]->(d)`,
	"DnsPointsTo":                  `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:DnsPointsTo {matched: r.via}]->(d)`,
	"ConnectedViaSG":               `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:ConnectedViaSG {via: r.via}]->(d)`,
	"AllowsFrom":                   `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:AllowsFrom {via: r.via}]->(d)`,
	"PeeredWith":                   `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:PeeredWith {via: r.via}]->(d)`,
	"ProtectedBy":                  `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:ProtectedBy {via: r.via}]->(d)`,
	"HasRole":                      `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:HasRole {via: r.via}]->(d)`,
	"ExecutesAs":                   `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:ExecutesAs {via: r.via}]->(d)`,
	"ExecutesAsK8sWorkload":        `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:ExecutesAsK8sWorkload {via: r.via}]->(d)`,
	"ExecutesAsK8sServiceAccount":  `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:K8sWorkload {id: r.dst}) CREATE (s)-[:ExecutesAsK8sServiceAccount {via: r.via}]->(d)`,
	"AccessesK8sWorkload":          `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:K8sWorkload {id: r.dst}) CREATE (s)-[:AccessesK8sWorkload {via: r.via}]->(d)`,
	"CanAssume":                    `UNWIND $rows AS r MATCH (s:IamRole {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:CanAssume {via: r.via}]->(d)`,
	"CanEscalateTo":                `UNWIND $rows AS r MATCH (s:IamRole {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:CanEscalateTo {via: r.via}]->(d)`,
	"DeploysTo":                    `UNWIND $rows AS r MATCH (s:Repo {id: r.src}), (d:K8sWorkload {id: r.dst}) CREATE (s)-[:DeploysTo {confidence: r.via}]->(d)`,
	"DeploysToService":             `UNWIND $rows AS r MATCH (s:Repo {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:DeploysToService {confidence: r.via}]->(d)`,
	"DependsOn":                    `UNWIND $rows AS r MATCH (s:Repo {id: r.src}), (d:Package {id: r.dst}) CREATE (s)-[:DependsOn {via: r.via}]->(d)`,
	"InVPC":                        `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:InVPC {via: r.via}]->(d)`,
	"Binds":                        `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:Binds {via: r.via}]->(d)`,
	"BindsK8sWorkload":             `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:BindsK8sWorkload {via: r.via}]->(d)`,
	"AccessesSecret":               `UNWIND $rows AS r MATCH (s:IamRole {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:AccessesSecret {via: r.via}]->(d)`,
	"FederatedAccess":              `UNWIND $rows AS r MATCH (s:Repo {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:FederatedAccess {trust_type: r.trust_type, subject: r.subject, provenance: r.provenance, confidence: r.confidence, workflow_path: r.workflow_path}]->(d)`,
	"FederatedAccessK8sWorkload":   `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:FederatedAccessK8sWorkload {trust_type: r.trust_type, subject: r.subject, provenance: r.provenance, confidence: r.confidence, workflow_path: r.workflow_path}]->(d)`,
	"FederatedAccessAsset":         `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:IamRole {id: r.dst}) CREATE (s)-[:FederatedAccessAsset {trust_type: r.trust_type, subject: r.subject, provenance: r.provenance, confidence: r.confidence, workflow_path: r.workflow_path}]->(d)`,
	"RunsPackage":                  `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Package {id: r.dst}) CREATE (s)-[:RunsPackage {via: r.via}]->(d)`,
	"RunsIn":                       `UNWIND $rows AS r MATCH (s:Package {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:RunsIn {via: r.via}]->(d)`,
	"Accesses":                     `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:Accesses {via: r.via}]->(d)`,
	// RunsImage's source is K8sWorkload (k8s_pod), not Asset, and the property
	// is image_ref, not via — buildEdgeRows does not populate via for this rel.
	// RunsImageAsset is the same edge from an Asset-labelled workload
	// (ecs_service, cloudrun_service).
	"RunsImage":      `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:RunsImage {image_ref: r.image_ref}]->(d)`,
	"RunsImageAsset": `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:RunsImageAsset {image_ref: r.image_ref}]->(d)`,
	"MemberOf":       "UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:`Group` {id: r.dst}) CREATE (s)-[:MemberOf {via: r.via}]->(d)",
	"MemberOfGroup":  "UNWIND $rows AS r MATCH (s:`Group` {id: r.src}), (d:`Group` {id: r.dst}) CREATE (s)-[:MemberOfGroup {via: r.via}]->(d)",
	"RunsContainer":  `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:RunsContainer {via: r.via}]->(d)`,
	"Owns":           `UNWIND $rows AS r MATCH (s:CloudAccount {id: r.src}), (d:Asset {id: r.dst}) CREATE (s)-[:Owns {via: r.via}]->(d)`,
	"OwnsAsset":      `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Repo {id: r.dst}) CREATE (s)-[:OwnsAsset {via: r.via}]->(d)`,
	"HasPolicy":      `UNWIND $rows AS r MATCH (s:IamRole {id: r.src}), (d:IamPolicy {id: r.dst}) CREATE (s)-[:HasPolicy {via: r.via}]->(d)`,
	"AllowsAction":   `UNWIND $rows AS r MATCH (s:IamRole {id: r.src}), (d:IamPolicy {id: r.dst}) CREATE (s)-[:AllowsAction {category: r.via}]->(d)`,
	"InSubnet":       `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Subnet {id: r.dst}) CREATE (s)-[:InSubnet {via: r.via}]->(d)`,
	"MemberOfZone":   `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:DNSZone {id: r.dst}) CREATE (s)-[:MemberOfZone {via: r.via}]->(d)`,
	// classification reads r.classification, not r.via — via's fallback chain
	// resolves to the generic `origin` property, which would make this column
	// noise regardless of the DataClass node it's attached to.
	"ContainsData":         `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:DataClass {id: r.dst}) CREATE (s)-[:ContainsData {classification: r.classification, confidence: r.confidence}]->(d)`,
	"AssignedTo":           "UNWIND $rows AS r MATCH (s:`Group` {id: r.src}), (d:PermissionSet {id: r.dst}) CREATE (s)-[:AssignedTo {confidence: r.confidence, provenance: r.provenance}]->(d)",
	"GrantsAccessTo":       `UNWIND $rows AS r MATCH (s:PermissionSet {id: r.src}), (d:CloudAccount {id: r.dst}) CREATE (s)-[:GrantsAccessTo {confidence: r.confidence, provenance: r.provenance}]->(d)`,
	"GrantsAdmin":          `UNWIND $rows AS r MATCH (s:PermissionSet {id: r.src}), (d:CloudAccount {id: r.dst}) CREATE (s)-[:GrantsAdmin {confidence: r.confidence, provenance: r.provenance}]->(d)`,
	"DefinedInK8sWorkload": `UNWIND $rows AS r MATCH (s:K8sWorkload {id: r.src}), (d:Repo {id: r.dst}) CREATE (s)-[:DefinedInK8sWorkload {confidence: r.confidence, provenance: r.provenance, path: r.path}]->(d)`,
	"DefinedInAsset":       `UNWIND $rows AS r MATCH (s:Asset {id: r.src}), (d:Repo {id: r.dst}) CREATE (s)-[:DefinedInAsset {confidence: r.confidence, provenance: r.provenance, path: r.path}]->(d)`,
	"DefinedInIamRole":     `UNWIND $rows AS r MATCH (s:IamRole {id: r.src}), (d:Repo {id: r.dst}) CREATE (s)-[:DefinedInIamRole {confidence: r.confidence, provenance: r.provenance}]->(d)`,
}

// unwindInsert prepares once and executes in batches of unwindBatchSize.
// Returns total rows successfully queued (Ladybug skips individual MATCH failures
// silently; only a Prepare/Execute structural error is returned).
func unwindInsert(conn *ladybug.Connection, query string, rows []map[string]any) (int, error) {
	if len(rows) == 0 {
		return 0, nil
	}
	prepared, err := conn.Prepare(query)
	if err != nil {
		return 0, fmt.Errorf("unwindInsert prepare: %w", err)
	}
	defer prepared.Close()

	total := 0
	for i := 0; i < len(rows); i += unwindBatchSize {
		end := min(i+unwindBatchSize, len(rows))
		batch := rows[i:end]
		rowList := make([]any, len(batch))
		for j, r := range batch {
			rowList[j] = r
		}
		res, err := conn.Execute(prepared, map[string]any{"rows": rowList})
		if err != nil {
			return total, fmt.Errorf("unwindInsert execute batch %d: %w", i/unwindBatchSize, err)
		}
		res.Close()
		total += len(batch)
	}
	return total, nil
}
