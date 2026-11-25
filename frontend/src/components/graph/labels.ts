// Pure label helpers shared by the graph canvas and its panels. Kept in their
// own module so panel components can import them without a circular dependency
// on GraphView.

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
