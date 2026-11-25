/**
 * Vulngraph Icon Registry - graph-native marks replacing lucide generics.
 *
 * All semantic security icons are from the Vulngraph Brand Guide.
 * Split by category into icons/*.tsx (see icons/shared.tsx for the shared design system);
 * this file is only the aggregation point.
 *
 * Usage:
 *   import { Shield, Brain, AlertTriangle } from "@/components/ui/icons"
 *   // Works exactly like Lucide - same props, same className
 *
 * Utility icons (X, ChevronRight, Loader2, etc.) are re-exported from
 * lucide-react below. You can import everything from this file instead of
 * lucide-react.
 */

export * from "./threat"
export * from "./identity"
export * from "./graph"
export * from "./data"
export * from "./nav"
export * from "./admin"
export * from "./finance"

// ── Explicit Lucide re-exports ────────────────────────────────────────────────
// NO WILDCARD. Every icon the app imports must be listed here — either as a
// graph-native custom above, or as an explicit re-export below. New icons
// added via `import { X } from "@/components/ui/icons"` will fail to compile
// unless explicitly registered, preventing silent Lucide fallthrough.
export {
  Archive,
  ArrowDownRight,
  ArrowLeft,
  ArrowLeftRight,
  ArrowUpDown,
  ArrowUpRight,
  Award,
  BarChart2,
  BookOpen,
  Box,
  BrainCircuit,
  Bug,
  Calendar,
  Check,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  ChevronUp,
  Circle,
  ClipboardCheck,
  Code2,
  Command,
  Copy,
  Crosshair,
  Cylinder,
  Download,
  Edit2,
  ExternalLink,
  EyeOff,
  FileCode,
  FileJson,
  FileWarning,
  Filter,
  Flame,
  FolderCode,
  FolderKey,
  GitCompare,
  GitMerge,
  Globe2,
  GraduationCap,
  HardDrive,
  Heart,
  History,
  Hourglass,
  Image,
  Inbox,
  Info,
  Laptop,
  LayoutGrid,
  Lightbulb,
  Link,
  Link2,
  List,
  ListChecks,
  Loader2,
  LockOpen,
  LogIn,
  MapPin,
  Maximize2,
  Menu,
  MessageCircle,
  Minimize2,
  Minus,
  MinusCircle,
  Monitor,
  MoreHorizontal,
  PackageCheck,
  PackageX,
  PanelLeft,
  PanelLeftClose,
  Paperclip,
  Pause,
  Pencil,
  PhoneCall,
  Pin,
  Play,
  Plus,
  Radar,
  Receipt,
  Recycle,
  Reply,
  RotateCcw,
  Route,
  Router,
  Save,
  Scale,
  Scan,
  ScanLine,
  Scissors,
  Settings2,
  Share2,
  ShieldOff,
  Slash,
  Smartphone,
  Sprout,
  StopCircle,
  Syringe,
  Table,
  Target,
  TestTube,
  ThumbsDown,
  ThumbsUp,
  Timer,
  ToggleLeft,
  ToggleRight,
  Trash2,
  Type,
  Upload,
  UserX,
  Wifi,
  WifiOff,
  Workflow,
  X,
} from "lucide-react"
