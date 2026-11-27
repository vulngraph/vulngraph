// Pure label helpers shared by the graph canvas and its panels. Kept in their
// own module so panel components can import them without a circular dependency
// on GraphView.

import schema from "../../generated/graph-schema.json";

// Cypher results label an edge with its Ladybug rel table (ExecutesAs,
// ExposedToInternetK8sWorkload); the rest of the canvas speaks edge types
// (executes_as). Rel tables split by endpoint label carry that label as a
// suffix, so the lookup also tries the name without it.
const RELS_BY_NAME = new Map<string, string>();
const ENDPOINT_SUFFIXES = ["K8sServiceAccount", "K8sWorkload", "IamRole", "Service", "Asset"];
function stripEndpointSuffix(name: string): string {
  const suffix = ENDPOINT_SUFFIXES.find((s) => name.endsWith(s) && name.length > s.length);
  return suffix ? name.slice(0, -suffix.length) : name;
}
// A rel several edge types share (Accesses holds routes_to, targets and
// runs_in) cannot say which one a result row was, so it is left unmapped.
const typesByRel = new Map<string, Set<string>>();
for (const { type, rel } of schema.edge_types) {
  for (const name of [rel, stripEndpointSuffix(rel)]) {
    const types = typesByRel.get(name) ?? typesByRel.set(name, new Set()).get(name)!;
    types.add(type);
  }
}
for (const [name, types] of typesByRel) if (types.size === 1) RELS_BY_NAME.set(name, [...types][0]);

// edgeType maps a rel table name to its edge type; anything else (already an
// edge type, or unknown) comes back unchanged.
export function edgeType(label: string): string {
  return RELS_BY_NAME.get(label) ?? RELS_BY_NAME.get(stripEndpointSuffix(label)) ?? label;
}

// edgeLabel converts snake_case edge types to short human labels.
export function edgeLabel(type: string): string {
  const map: Record<string, string> = {
    protected_by: "protects", runs_in: "runs in", can_assume: "can assume",
    deploys_to: "deploys", exposed_to_internet: "exposed", dns_points_to: "DNS",
    sg_allows_from: "allows", applies_to: "applies", in_vpc: "in VPC",
    executes_as: "executes as", can_escalate: "escalates", can_escalate_to: "escalates to",
  };
  return map[type] ?? type.replace(/_/g, " ");
}

// shortenLabel makes node labels readable — strips provider prefixes and paths.
export function shortenLabel(label: string): string {
  const arnUser = label.match(/arn:[^:]+:[^:]+::[^:]*:(?:user|role)\/(.+)$/);
  if (arnUser) return arnUser[1].split("/").pop() ?? label;
  const gcpRes = label.match(/\/([^/]+)$/);
  if (gcpRes && label.startsWith("//")) return gcpRes[1];
  const pkg = label.match(/\/([^/@]+(?:@[^/]+)?)$/);
  if (pkg && label.startsWith("pkg:")) return pkg[1];
  if (label.length > 28) return label.slice(0, 13) + "…" + label.slice(-10);
  return label;
}

// typeLabel converts snake_case type to a short human label.
export function typeLabel(type: string): string {
  const map: Record<string, string> = {
    ec2_instance: "EC2", gce_instance: "GCE", iam_role: "IAM Role", iam_user: "IAM User",
    gcp_service_account: "SA", security_group: "SG", vpc_network: "VPC", subnet: "Subnet",
    s3_bucket: "S3", gcs_bucket: "GCS", k8s_pod: "Pod", k8s_deployment: "Deploy",
    k8s_service: "Service", k8s_namespace: "NS", load_balancer: "LB",
    github_repo: "Repo", gcp_firewall: "Firewall",
  };
  return map[type] ?? type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
