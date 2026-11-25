import {
  ArrowLeftRight,
  Award,
  AtSign,
  Boxes,
  Box,
  Building2,
  Container,
  Cpu,
  Cylinder,
  Database,
  FolderGit2,
  Globe,
  GitBranch,
  HardDrive,
  KeyRound,
  Layers,
  Lock,
  Route,
  Server,
  ShieldCheck,
  Sigma,
  Webhook,
  Wifi,
  Zap,
  type LucideIcon,
} from "lucide-react";
import { timeAgo as timeAgoBase } from "./format";

// Visual metadata for asset rows — maps a backend asset `type` to an icon + tint,
// and a `provider` to a brand colour. Unknown types fall back to a neutral Box.

type TypeMeta = { icon: LucideIcon; color: string; bg: string; label: string };

const typeMeta: Record<string, TypeMeta> = {
  // ── Compute ───────────────────────────────────────────────────────────────
  ec2_instance:        { icon: Server,         color: "text-teal",     bg: "bg-teal/10",      label: "EC2" },
  gce_instance:        { icon: Server,         color: "text-sky",      bg: "bg-sky/10",       label: "GCE" },
  azure_vm:            { icon: Server,         color: "text-blue-400", bg: "bg-blue-400/10",  label: "VM" },
  lambda_function:     { icon: Zap,            color: "text-emerald",  bg: "bg-emerald/10",   label: "Lambda" },
  gcp_function:        { icon: Zap,            color: "text-sky",      bg: "bg-sky/10",       label: "Function" },
  ecs_service:         { icon: Cpu,            color: "text-teal",     bg: "bg-teal/10",      label: "ECS" },
  ecs_cluster:         { icon: Boxes,          color: "text-teal",     bg: "bg-teal/10",      label: "ECS Cluster" },

  // ── Databases ─────────────────────────────────────────────────────────────
  rds_instance:        { icon: Database,       color: "text-red",      bg: "bg-red/10",       label: "RDS" },
  cloud_sql:           { icon: Database,       color: "text-sky",      bg: "bg-sky/10",       label: "Cloud SQL" },
  azure_sql_server:    { icon: Database,       color: "text-blue-400", bg: "bg-blue-400/10",  label: "SQL Server" },
  azure_sql_database:  { icon: Database,       color: "text-blue-400", bg: "bg-blue-400/10",  label: "SQL DB" },
  dynamodb_table:      { icon: Database,       color: "text-amber",    bg: "bg-amber/10",     label: "DynamoDB" },

  // ── Storage ───────────────────────────────────────────────────────────────
  s3_bucket:           { icon: Cylinder,       color: "text-emerald",  bg: "bg-emerald/10",   label: "S3" },
  gcs_bucket:          { icon: Cylinder,       color: "text-sky",      bg: "bg-sky/10",       label: "GCS" },
  azure_storage:       { icon: Cylinder,       color: "text-blue-400", bg: "bg-blue-400/10",  label: "Blob" },
  ebs_volume:          { icon: HardDrive,      color: "text-text-2",   bg: "bg-surface-3",    label: "EBS" },

  // ── Networking ────────────────────────────────────────────────────────────
  vpc:                 { icon: Wifi,           color: "text-teal",     bg: "bg-teal/10",      label: "VPC" },
  vpc_network:         { icon: Wifi,           color: "text-sky",      bg: "bg-sky/10",       label: "VPC" },
  azure_vnet:          { icon: Wifi,           color: "text-blue-400", bg: "bg-blue-400/10",  label: "VNet" },
  subnet:              { icon: Route,          color: "text-text-2",   bg: "bg-surface-3",    label: "Subnet" },
  azure_subnet:        { icon: Route,          color: "text-blue-400", bg: "bg-blue-400/10",  label: "Subnet" },
  load_balancer:       { icon: ArrowLeftRight, color: "text-teal",     bg: "bg-teal/10",      label: "LB" },
  gcp_forwarding_rule: { icon: ArrowLeftRight, color: "text-sky",      bg: "bg-sky/10",       label: "LB" },
  security_group:      { icon: ShieldCheck,    color: "text-amber",    bg: "bg-amber/10",     label: "SG" },
  firewall:            { icon: ShieldCheck,    color: "text-amber",    bg: "bg-amber/10",     label: "FW" },
  elastic_ip:          { icon: Globe,          color: "text-teal",     bg: "bg-teal/10",      label: "EIP" },
  dns_record:          { icon: AtSign,         color: "text-text-2",   bg: "bg-surface-3",    label: "DNS" },
  dns_zone:            { icon: AtSign,         color: "text-text-2",   bg: "bg-surface-3",    label: "Zone" },
  api_gateway:         { icon: Webhook,        color: "text-teal",     bg: "bg-teal/10",      label: "API GW" },

  // ── Identity ──────────────────────────────────────────────────────────────
  iam_role:            { icon: KeyRound,       color: "text-amber",    bg: "bg-amber/10",     label: "Role" },
  iam_user:            { icon: KeyRound,       color: "text-amber",    bg: "bg-amber/10",     label: "IAM User" },
  iam_policy:          { icon: Lock,           color: "text-amber",    bg: "bg-amber/10",     label: "Policy" },
  service_account:     { icon: KeyRound,       color: "text-sky",      bg: "bg-sky/10",       label: "SA" },
  gcp_service_account: { icon: KeyRound,       color: "text-sky",      bg: "bg-sky/10",       label: "SA" },
  cloud_account:       { icon: Building2,      color: "text-text-2",   bg: "bg-surface-3",    label: "Account" },
  azure_subscription:  { icon: Building2,      color: "text-blue-400", bg: "bg-blue-400/10",  label: "Subscription" },

  // ── Certificates & Secrets ────────────────────────────────────────────────
  acm_certificate:     { icon: Award,          color: "text-teal",     bg: "bg-teal/10",      label: "Cert" },
  gcp_certificate:     { icon: Award,          color: "text-sky",      bg: "bg-sky/10",       label: "Cert" },
  ssl_certificate:     { icon: Award,          color: "text-teal",     bg: "bg-teal/10",      label: "Cert" },
  gcp_secret:          { icon: Lock,           color: "text-amber",    bg: "bg-amber/10",     label: "Secret" },
  kms_key:             { icon: KeyRound,       color: "text-red",      bg: "bg-red/10",       label: "KMS" },

  // ── Kubernetes ────────────────────────────────────────────────────────────
  kubernetes_workload: { icon: Container,      color: "text-sky",      bg: "bg-sky/10",       label: "Workload" },
  kubernetes_pod:      { icon: Container,      color: "text-sky",      bg: "bg-sky/10",       label: "Pod" },
  k8s_pod:             { icon: Container,      color: "text-sky",      bg: "bg-sky/10",       label: "Pod" },
  k8s_deployment:      { icon: Layers,         color: "text-sky",      bg: "bg-sky/10",       label: "Deploy" },
  k8s_service:         { icon: ArrowLeftRight, color: "text-sky",      bg: "bg-sky/10",       label: "Service" },
  k8s_workload:        { icon: Container,      color: "text-sky",      bg: "bg-sky/10",       label: "Workload" },
  gke_cluster:         { icon: Boxes,          color: "text-sky",      bg: "bg-sky/10",       label: "GKE" },
  eks_cluster:         { icon: Boxes,          color: "text-teal",     bg: "bg-teal/10",      label: "EKS" },

  // ── Code & Supply chain ───────────────────────────────────────────────────
  github_repo:         { icon: FolderGit2,     color: "text-text-2",   bg: "bg-surface-3",    label: "Repo" },
  package:             { icon: GitBranch,      color: "text-text-3",   bg: "bg-surface",      label: "Package" },
  container_image:     { icon: Container,      color: "text-text-2",   bg: "bg-surface-3",    label: "Image" },

  // ── Observability ─────────────────────────────────────────────────────────
  aws_cloudtrail:      { icon: Sigma,          color: "text-text-2",   bg: "bg-surface-3",    label: "CloudTrail" },
};

const fallbackType: TypeMeta = { icon: Box, color: "text-text-3", bg: "bg-surface", label: "" };

export function typeMetaFor(type: string): TypeMeta {
  return typeMeta[type] ?? fallbackType;
}

const providerColor: Record<string, string> = {
  aws: "text-orange border-orange/30 bg-orange/10",
  gcp: "text-sky border-sky/30 bg-sky/10",
  github: "text-text-2 border-border-subtle bg-surface",
  kubernetes: "text-teal border-teal/30 bg-teal/10",
  azure: "text-blue-400 border-blue-400/30 bg-blue-400/10",
};

export function providerClass(provider: string): string {
  return providerColor[provider] ?? "text-text-3 border-border-subtle bg-surface";
}

export const GlobeIcon = Globe;

// timeAgo renders a compact relative time ("just now", "5m", "2h", "3d", "4w").
// Re-exported (as the "compact" style) from lib/format.ts's merged timeAgo, for
// callers that still import it from here.
export function timeAgo(iso?: string): string {
  return timeAgoBase(iso, "compact");
}
