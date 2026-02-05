import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { LineChart, Line, AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Treemap } from "recharts";
import { Shield, AlertTriangle, Cloud, Lock, Eye, Activity, Server, Database, Users, Key, GitBranch, Layers, Search, Bell, Settings, ChevronDown, ChevronRight, X, Check, AlertCircle, Info, Zap, Globe, Box, Terminal, FileText, Filter, Download, RefreshCw, BarChart2, PieChart as PieChartIcon, TrendingUp, TrendingDown, ArrowRight, ExternalLink, Clock, MapPin, Cpu, HardDrive, Wifi, Share2, Target, Crosshair, ShieldAlert, ShieldCheck, UserCheck, UserX, KeyRound, Network, Scan, Bug, FileWarning, CheckCircle, XCircle, Minus } from "lucide-react";

// ─── MOCK DATA ENGINE ────────────────────────────────────────────────────────
const CLOUD_PROVIDERS = ["AWS", "Azure", "GCP"];
const SEVERITY = { CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", INFO: "info" };
const COLORS = { critical: "#ff1744", high: "#ff6d00", medium: "#ffc400", low: "#00e676", info: "#448aff" };
const PROVIDER_COLORS = { AWS: "#FF9900", Azure: "#0078D4", GCP: "#4285F4" };

const generateSecurityScore = () => Math.floor(Math.random() * 30) + 65;
const generateTrend = (days = 30, base = 50) => Array.from({ length: days }, (_, i) => ({
  date: new Date(Date.now() - (days - i) * 86400000).toLocaleDateString("en-US", { month: "short", day: "numeric" }),
  value: Math.max(0, base + Math.floor(Math.random() * 20 - 10) + Math.floor(i * 0.3)),
  resolved: Math.floor(Math.random() * 15) + 5,
  newFindings: Math.floor(Math.random() * 10) + 2,
}));

const MOCK_ASSETS = {
  total: 14832,
  breakdown: [
    { name: "EC2 Instances", count: 3421, provider: "AWS", risk: 23 },
    { name: "S3 Buckets", count: 847, provider: "AWS", risk: 12 },
    { name: "Lambda Functions", count: 2156, provider: "AWS", risk: 8 },
    { name: "RDS Databases", count: 234, provider: "AWS", risk: 31 },
    { name: "Virtual Machines", count: 1893, provider: "Azure", risk: 19 },
    { name: "Storage Accounts", count: 562, provider: "Azure", risk: 14 },
    { name: "AKS Clusters", count: 89, provider: "Azure", risk: 27 },
    { name: "Azure Functions", count: 1245, provider: "Azure", risk: 6 },
    { name: "GCE Instances", count: 1678, provider: "GCP", risk: 17 },
    { name: "GCS Buckets", count: 923, provider: "GCP", risk: 9 },
    { name: "Cloud Functions", count: 1456, provider: "GCP", risk: 5 },
    { name: "Cloud SQL", count: 328, provider: "GCP", risk: 22 },
  ],
};

const MOCK_FINDINGS = [
  { id: "CF-2026-0001", title: "S3 Bucket Publicly Accessible with Sensitive Data", severity: "critical", provider: "AWS", resource: "arn:aws:s3:::prod-customer-data", category: "CSPM", framework: "CIS AWS 2.0", status: "open", age: 3, attackPath: true },
  { id: "CF-2026-0002", title: "IAM Role with AdministratorAccess and No MFA", severity: "critical", provider: "AWS", resource: "arn:aws:iam::123456789:role/LegacyAdmin", category: "CIEM", framework: "SOC 2", status: "open", age: 14, attackPath: true },
  { id: "CF-2026-0003", title: "Critical CVE-2026-1234 in Container Base Image", severity: "critical", provider: "GCP", resource: "gcr.io/prod/api-server:latest", category: "CWPP", framework: "NIST 800-53", status: "in_progress", age: 1, attackPath: true },
  { id: "CF-2026-0004", title: "Azure Storage Account Allows Anonymous Access", severity: "high", provider: "Azure", resource: "/subscriptions/xxx/storageAccounts/prodlogs", category: "CSPM", framework: "CIS Azure 2.0", status: "open", age: 7, attackPath: false },
  { id: "CF-2026-0005", title: "Cross-Account Role Assumption Without External ID", severity: "high", provider: "AWS", resource: "arn:aws:iam::987654321:role/CrossAcctDeploy", category: "CIEM", framework: "CIS AWS 2.0", status: "open", age: 21, attackPath: true },
  { id: "CF-2026-0006", title: "Kubernetes Pod Running as Root with Host Network", severity: "high", provider: "Azure", resource: "aks-prod/default/legacy-worker", category: "CWPP", framework: "CIS Kubernetes 1.8", status: "open", age: 5, attackPath: true },
  { id: "CF-2026-0007", title: "Unused Service Account Key Older Than 90 Days", severity: "medium", provider: "GCP", resource: "projects/prod/serviceAccounts/deploy@prod.iam", category: "CIEM", framework: "CIS GCP 2.0", status: "open", age: 92, attackPath: false },
  { id: "CF-2026-0008", title: "Security Group Allows Ingress 0.0.0.0/0 on SSH", severity: "high", provider: "AWS", resource: "sg-0a1b2c3d4e5f6g7h8", category: "CSPM", framework: "PCI DSS 4.0", status: "in_progress", age: 2, attackPath: true },
  { id: "CF-2026-0009", title: "Encryption at Rest Disabled on RDS Instance", severity: "medium", provider: "AWS", resource: "arn:aws:rds:us-east-1:123456789:db/analytics", category: "CSPM", framework: "HIPAA", status: "open", age: 45, attackPath: false },
  { id: "CF-2026-0010", title: "GCP Compute Instance with Default Service Account", severity: "medium", provider: "GCP", resource: "projects/prod/zones/us-central1-a/instances/worker-7", category: "CIEM", framework: "CIS GCP 2.0", status: "open", age: 30, attackPath: false },
];

const MOCK_IDENTITIES = {
  total: 8934,
  overPrivileged: 1247,
  inactive: 2341,
  noMFA: 892,
  crossAccount: 156,
  serviceAccounts: 3421,
  humanIdentities: 5513,
  thirdParty: 234,
  permissionGap: 67.3,
  toxicCombinations: 43,
  adminAccess: 312,
  breakdown: [
    { name: "Over-Privileged", value: 1247, color: "#ff6d00" },
    { name: "Inactive 90d+", value: 2341, color: "#ffc400" },
    { name: "No MFA", value: 892, color: "#ff1744" },
    { name: "Compliant", value: 4454, color: "#00e676" },
  ],
};

const MOCK_COMPLIANCE = [
  { name: "SOC 2 Type II", score: 87, controls: 264, passing: 230, failing: 34, provider: "All" },
  { name: "CIS AWS 2.0", score: 79, controls: 198, passing: 156, failing: 42, provider: "AWS" },
  { name: "CIS Azure 2.0", score: 82, controls: 176, passing: 144, failing: 32, provider: "Azure" },
  { name: "CIS GCP 2.0", score: 85, controls: 154, passing: 131, failing: 23, provider: "GCP" },
  { name: "PCI DSS 4.0", score: 91, controls: 312, passing: 284, failing: 28, provider: "All" },
  { name: "HIPAA", score: 88, controls: 145, passing: 128, failing: 17, provider: "All" },
  { name: "NIST 800-53", score: 76, controls: 421, passing: 320, failing: 101, provider: "All" },
  { name: "ISO 27001", score: 83, controls: 114, passing: 95, failing: 19, provider: "All" },
  { name: "GDPR", score: 90, controls: 89, passing: 80, failing: 9, provider: "All" },
  { name: "FedRAMP High", score: 74, controls: 456, passing: 337, failing: 119, provider: "All" },
];

const MOCK_ATTACK_PATHS = [
  { id: "AP-001", name: "Internet → S3 → RDS Data Exfiltration", severity: "critical", steps: 4, assets: 7, blast: "12,400 records", probability: "High" },
  { id: "AP-002", name: "Compromised Lambda → Cross-Account Pivot", severity: "critical", steps: 3, assets: 5, blast: "3 AWS accounts", probability: "Medium" },
  { id: "AP-003", name: "Public VM → Metadata SSRF → IAM Credential Theft", severity: "high", steps: 5, assets: 4, blast: "Admin access", probability: "High" },
  { id: "AP-004", name: "Exposed K8s API → Container Escape → Host", severity: "high", steps: 4, assets: 6, blast: "AKS cluster", probability: "Medium" },
  { id: "AP-005", name: "Third-Party SaaS → OAuth Token → Data Access", severity: "medium", steps: 3, assets: 3, blast: "Drive files", probability: "Low" },
];

const MOCK_VULNS = {
  total: 4521,
  critical: 89,
  high: 423,
  medium: 1876,
  low: 2133,
  trend: generateTrend(30, 40),
  topCVEs: [
    { id: "CVE-2026-1234", score: 9.8, affected: 34, title: "Remote Code Execution in libxml2", exploited: true },
    { id: "CVE-2026-0891", score: 9.6, affected: 21, title: "Auth Bypass in OpenSSH 9.x", exploited: true },
    { id: "CVE-2025-4567", score: 9.1, affected: 67, title: "Container Escape via runc", exploited: false },
    { id: "CVE-2026-2345", score: 8.9, affected: 12, title: "SQL Injection in PostgreSQL Driver", exploited: false },
    { id: "CVE-2025-8901", score: 8.7, affected: 89, title: "XSS in React Server Components", exploited: false },
  ],
};

const MOCK_CONTAINERS = {
  clusters: 23,
  pods: 4521,
  images: 897,
  registries: 12,
  misconfigs: 234,
  vulnerableImages: 156,
  privilegedPods: 43,
  outdatedImages: 312,
};

const MOCK_IAC = {
  totalScans: 1245,
  findings: 3421,
  repos: 87,
  driftDetected: 156,
  blockedDeploys: 23,
};

// ─── COMPONENT LIBRARY ──────────────────────────────────────────────────────
const SeverityBadge = ({ severity }) => {
  const styles = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    info: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wider border ${styles[severity] || styles.info}`}>
      {severity}
    </span>
  );
};

const StatusBadge = ({ status }) => {
  const styles = {
    open: "bg-red-500/10 text-red-400",
    in_progress: "bg-yellow-500/10 text-yellow-400",
    resolved: "bg-emerald-500/10 text-emerald-400",
    suppressed: "bg-zinc-500/10 text-zinc-400",
  };
  const labels = { open: "Open", in_progress: "In Progress", resolved: "Resolved", suppressed: "Suppressed" };
  return <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[status]}`}>{labels[status]}</span>;
};

const ProviderIcon = ({ provider, size = 16 }) => {
  const colors = PROVIDER_COLORS;
  return (
    <span className="inline-flex items-center gap-1 text-xs font-bold" style={{ color: colors[provider] }}>
      <Cloud size={size} /> {provider}
    </span>
  );
};

const MetricCard = ({ icon: Icon, label, value, change, changeType, color = "#448aff", subtitle, onClick }) => (
  <div onClick={onClick} className={`bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 hover:border-zinc-700 transition-all duration-300 ${onClick ? "cursor-pointer hover:bg-zinc-800/60" : ""}`}>
    <div className="flex items-start justify-between mb-3">
      <div className="p-2 rounded-lg" style={{ background: `${color}15` }}>
        <Icon size={20} style={{ color }} />
      </div>
      {change !== undefined && (
        <span className={`flex items-center gap-1 text-xs font-medium ${changeType === "up" ? "text-emerald-400" : changeType === "down" ? "text-red-400" : "text-zinc-500"}`}>
          {changeType === "up" ? <TrendingUp size={12} /> : changeType === "down" ? <TrendingDown size={12} /> : <Minus size={12} />}
          {change}
        </span>
      )}
    </div>
    <div className="text-2xl font-bold text-white tracking-tight">{typeof value === "number" ? value.toLocaleString() : value}</div>
    <div className="text-xs text-zinc-500 mt-1">{label}</div>
    {subtitle && <div className="text-xs text-zinc-600 mt-0.5">{subtitle}</div>}
  </div>
);

const ScoreGauge = ({ score, size = 120, label, sublabel }) => {
  const circumference = 2 * Math.PI * 45;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? "#00e676" : score >= 60 ? "#ffc400" : "#ff1744";
  return (
    <div className="flex flex-col items-center">
      <svg width={size} height={size} viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="45" fill="none" stroke="#27272a" strokeWidth="6" />
        <circle cx="50" cy="50" r="45" fill="none" stroke={color} strokeWidth="6" strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          transform="rotate(-90 50 50)" style={{ transition: "stroke-dashoffset 1s ease" }} />
        <text x="50" y="46" textAnchor="middle" fill="white" fontSize="22" fontWeight="bold" fontFamily="monospace">{score}</text>
        <text x="50" y="60" textAnchor="middle" fill="#71717a" fontSize="8">/100</text>
      </svg>
      {label && <div className="text-sm font-medium text-zinc-300 mt-2">{label}</div>}
      {sublabel && <div className="text-xs text-zinc-600">{sublabel}</div>}
    </div>
  );
};

const ProgressBar = ({ value, max = 100, color = "#448aff", height = 6, showLabel = false }) => (
  <div className="w-full">
    <div className="w-full rounded-full overflow-hidden" style={{ height, background: "#27272a" }}>
      <div className="h-full rounded-full transition-all duration-700" style={{ width: `${(value / max) * 100}%`, background: color }} />
    </div>
    {showLabel && <div className="text-xs text-zinc-500 mt-1">{value}/{max}</div>}
  </div>
);

// ─── SECURITY GRAPH VISUALIZATION ────────────────────────────────────────────
const SecurityGraph = () => {
  const canvasRef = useRef(null);
  const [hoveredNode, setHoveredNode] = useState(null);
  const nodesRef = useRef([]);
  const edgesRef = useRef([]);
  const animRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const W = canvas.width = canvas.offsetWidth * 2;
    const H = canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);
    const w = W / 2, h = H / 2;

    const nodeTypes = [
      { type: "internet", icon: "🌐", color: "#ff1744", x: 80, y: h / 2 },
      { type: "lb", icon: "⚖️", color: "#ff6d00", x: 180, y: h / 2 - 40 },
      { type: "waf", icon: "🛡", color: "#00e676", x: 180, y: h / 2 + 40 },
      { type: "ec2-1", icon: "🖥", color: "#448aff", x: 300, y: h / 2 - 80 },
      { type: "ec2-2", icon: "🖥", color: "#448aff", x: 300, y: h / 2 },
      { type: "lambda", icon: "λ", color: "#ffc400", x: 300, y: h / 2 + 80 },
      { type: "iam-role", icon: "🔑", color: "#ff1744", x: 420, y: h / 2 - 120 },
      { type: "s3", icon: "📦", color: "#ff6d00", x: 420, y: h / 2 - 40 },
      { type: "rds", icon: "🗄", color: "#ff1744", x: 420, y: h / 2 + 40 },
      { type: "secrets", icon: "🔒", color: "#00e676", x: 420, y: h / 2 + 120 },
      { type: "k8s", icon: "☸", color: "#448aff", x: 540, y: h / 2 - 60 },
      { type: "ecr", icon: "📋", color: "#ffc400", x: 540, y: h / 2 + 60 },
      { type: "cross-acct", icon: "🔗", color: "#ff1744", x: 650, y: h / 2 },
    ];

    const edges = [
      [0, 1], [0, 2], [1, 3], [1, 4], [2, 4], [2, 5],
      [3, 6], [3, 7], [4, 7], [4, 8], [5, 8], [5, 9],
      [6, 10], [7, 10], [7, 11], [8, 11], [10, 12], [6, 12],
    ];

    nodesRef.current = nodeTypes;
    edgesRef.current = edges;

    let frame = 0;
    const animate = () => {
      frame++;
      ctx.clearRect(0, 0, w, h);

      // Draw edges
      edges.forEach(([from, to]) => {
        const a = nodeTypes[from], b = nodeTypes[to];
        const isAttackPath = [0, 1, 3, 6, 12].includes(from) && [1, 3, 6, 12].includes(to);
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = isAttackPath ? `rgba(255,23,68,${0.3 + Math.sin(frame * 0.03) * 0.2})` : "rgba(63,63,70,0.5)";
        ctx.lineWidth = isAttackPath ? 2 : 1;
        if (isAttackPath) ctx.setLineDash([5, 5]);
        else ctx.setLineDash([]);
        ctx.stroke();
        ctx.setLineDash([]);

        // Animated particles on attack path
        if (isAttackPath) {
          const t = ((frame * 2) % 200) / 200;
          const px = a.x + (b.x - a.x) * t;
          const py = a.y + (b.y - a.y) * t;
          ctx.beginPath();
          ctx.arc(px, py, 3, 0, Math.PI * 2);
          ctx.fillStyle = "#ff1744";
          ctx.fill();
        }
      });

      // Draw nodes
      nodeTypes.forEach((node, i) => {
        const pulse = node.color === "#ff1744" ? Math.sin(frame * 0.05) * 4 : 0;
        // Glow
        const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, 28 + pulse);
        grad.addColorStop(0, node.color + "40");
        grad.addColorStop(1, node.color + "00");
        ctx.beginPath();
        ctx.arc(node.x, node.y, 28 + pulse, 0, Math.PI * 2);
        ctx.fillStyle = grad;
        ctx.fill();

        // Node circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, 18, 0, Math.PI * 2);
        ctx.fillStyle = "#18181b";
        ctx.strokeStyle = node.color + "80";
        ctx.lineWidth = 2;
        ctx.fill();
        ctx.stroke();

        // Icon
        ctx.font = "14px sans-serif";
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillStyle = "white";
        ctx.fillText(node.icon, node.x, node.y);

        // Label
        ctx.font = "9px monospace";
        ctx.fillStyle = "#a1a1aa";
        ctx.fillText(node.type, node.x, node.y + 30);
      });

      // Title
      ctx.font = "bold 11px monospace";
      ctx.fillStyle = "#ff1744";
      ctx.textAlign = "left";
      ctx.fillText("⚡ ACTIVE ATTACK PATH: Internet → LB → EC2 → IAM → Cross-Account", 20, 20);

      animRef.current = requestAnimationFrame(animate);
    };
    animate();
    return () => cancelAnimationFrame(animRef.current);
  }, []);

  return (
    <div className="relative w-full h-full min-h-[300px]">
      <canvas ref={canvasRef} className="w-full h-full" style={{ display: "block" }} />
    </div>
  );
};

// ─── ATTACK PATH VISUALIZATION ───────────────────────────────────────────────
const AttackPathDiagram = ({ path }) => {
  const steps = [
    { label: "Internet Exposure", icon: Globe, color: "#ff1744" },
    { label: "Initial Access", icon: Terminal, color: "#ff6d00" },
    { label: "Lateral Movement", icon: Share2, color: "#ffc400" },
    { label: "Data Exfiltration", icon: Database, color: "#ff1744" },
  ];
  return (
    <div className="flex items-center gap-2 py-3 overflow-x-auto">
      {steps.slice(0, path.steps).map((step, i) => (
        <div key={i} className="flex items-center gap-2">
          <div className="flex flex-col items-center gap-1 min-w-[80px]">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center border" style={{ borderColor: step.color + "40", background: step.color + "15" }}>
              <step.icon size={18} style={{ color: step.color }} />
            </div>
            <span className="text-[10px] text-zinc-500 text-center">{step.label}</span>
          </div>
          {i < path.steps - 1 && <ArrowRight size={14} className="text-zinc-600 flex-shrink-0" />}
        </div>
      ))}
    </div>
  );
};

// ─── IDENTITY GRAPH (CIEM) ───────────────────────────────────────────────────
const IdentityRiskMatrix = () => {
  const data = [
    { name: "Admin\nAccess", permissions: 95, usage: 12, risk: 92, identities: 43 },
    { name: "Cross\nAccount", permissions: 78, usage: 23, risk: 76, identities: 156 },
    { name: "Service\nAccounts", permissions: 65, usage: 67, risk: 34, identities: 3421 },
    { name: "Human\nUsers", permissions: 45, usage: 78, risk: 28, identities: 5513 },
    { name: "Third\nParty", permissions: 82, usage: 15, risk: 85, identities: 234 },
    { name: "Federated", permissions: 55, usage: 45, risk: 42, identities: 892 },
  ];
  return (
    <ResponsiveContainer width="100%" height={250}>
      <RadarChart data={data}>
        <PolarGrid stroke="#27272a" />
        <PolarAngleAxis dataKey="name" tick={{ fill: "#71717a", fontSize: 10 }} />
        <Radar name="Permissions" dataKey="permissions" stroke="#ff6d00" fill="#ff6d00" fillOpacity={0.15} strokeWidth={2} />
        <Radar name="Usage" dataKey="usage" stroke="#00e676" fill="#00e676" fillOpacity={0.1} strokeWidth={2} />
        <Radar name="Risk" dataKey="risk" stroke="#ff1744" fill="#ff1744" fillOpacity={0.1} strokeWidth={2} />
        <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
      </RadarChart>
    </ResponsiveContainer>
  );
};

// ─── MAIN APP ────────────────────────────────────────────────────────────────
const NAV_ITEMS = [
  { id: "overview", label: "Overview", icon: BarChart2 },
  { id: "graph", label: "Security Graph", icon: Share2 },
  { id: "cspm", label: "CSPM", icon: Shield },
  { id: "ciem", label: "CIEM", icon: Users },
  { id: "cwpp", label: "CWPP", icon: Server },
  { id: "vulns", label: "Vulnerabilities", icon: Bug },
  { id: "containers", label: "Containers", icon: Box },
  { id: "attack-paths", label: "Attack Paths", icon: Crosshair },
  { id: "compliance", label: "Compliance", icon: CheckCircle },
  { id: "iac", label: "IaC Security", icon: GitBranch },
  { id: "inventory", label: "Asset Inventory", icon: Database },
  { id: "alerts", label: "Alerts", icon: Bell },
];

export default function CloudFortressApp() {
  const [activeView, setActiveView] = useState("overview");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedProvider, setSelectedProvider] = useState("All");
  const [showNotifications, setShowNotifications] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [darkPulse, setDarkPulse] = useState(true);
  const trendData = useMemo(() => generateTrend(30, 45), []);
  const securityScore = useMemo(() => 72, []);

  const filteredFindings = useMemo(() =>
    MOCK_FINDINGS.filter(f =>
      (selectedProvider === "All" || f.provider === selectedProvider) &&
      (!searchQuery || f.title.toLowerCase().includes(searchQuery.toLowerCase()) || f.id.toLowerCase().includes(searchQuery.toLowerCase()))
    ), [selectedProvider, searchQuery]);

  // ─── OVERVIEW DASHBOARD ──────────────────────────────────────────────────
  const OverviewView = () => (
    <div className="space-y-6">
      {/* Top Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4">
        <MetricCard icon={Shield} label="Security Score" value={securityScore} change="+3" changeType="up" color="#448aff" />
        <MetricCard icon={AlertTriangle} label="Critical Findings" value={MOCK_FINDINGS.filter(f => f.severity === "critical").length} change="-2" changeType="up" color="#ff1744" onClick={() => setActiveView("cspm")} />
        <MetricCard icon={Users} label="Over-Privileged" value={MOCK_IDENTITIES.overPrivileged} change="-12%" changeType="up" color="#ff6d00" onClick={() => setActiveView("ciem")} />
        <MetricCard icon={Bug} label="Vulnerabilities" value={MOCK_VULNS.total} change="+34" changeType="down" color="#ffc400" onClick={() => setActiveView("vulns")} />
        <MetricCard icon={Crosshair} label="Attack Paths" value={MOCK_ATTACK_PATHS.length} change="2 critical" changeType="down" color="#ff1744" onClick={() => setActiveView("attack-paths")} />
        <MetricCard icon={Database} label="Total Assets" value={MOCK_ASSETS.total} change="+124" changeType="up" color="#00e676" onClick={() => setActiveView("inventory")} />
      </div>

      {/* Security Score + Graph */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Security Posture</h3>
          <div className="flex items-center justify-around">
            <ScoreGauge score={securityScore} label="Overall" sublabel="Multi-Cloud" />
            <div className="space-y-4">
              {CLOUD_PROVIDERS.map(p => (
                <div key={p} className="flex items-center gap-3">
                  <ProviderIcon provider={p} />
                  <ProgressBar value={p === "AWS" ? 68 : p === "Azure" ? 74 : 81} color={PROVIDER_COLORS[p]} />
                  <span className="text-xs text-zinc-400 w-8">{p === "AWS" ? 68 : p === "Azure" ? 74 : 81}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="xl:col-span-2 bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Findings Trend (30d)</h3>
            <div className="flex gap-4 text-xs">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" />New</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" />Resolved</span>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="date" tick={{ fill: "#71717a", fontSize: 10 }} tickLine={false} axisLine={false} interval={4} />
              <YAxis tick={{ fill: "#71717a", fontSize: 10 }} tickLine={false} axisLine={false} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
              <Area type="monotone" dataKey="newFindings" stroke="#ff1744" fill="#ff174420" strokeWidth={2} />
              <Area type="monotone" dataKey="resolved" stroke="#00e676" fill="#00e67620" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Critical Findings + Attack Paths */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Critical Findings</h3>
            <button onClick={() => setActiveView("cspm")} className="text-xs text-blue-400 hover:text-blue-300">View all →</button>
          </div>
          <div className="space-y-3">
            {MOCK_FINDINGS.filter(f => f.severity === "critical").map(f => (
              <div key={f.id} className="p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50 hover:border-red-500/30 transition-colors cursor-pointer" onClick={() => setSelectedFinding(f)}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={f.severity} />
                      <ProviderIcon provider={f.provider} size={12} />
                      {f.attackPath && <span className="text-[10px] text-red-400 flex items-center gap-1"><Crosshair size={10} />Attack Path</span>}
                    </div>
                    <p className="text-sm text-zinc-200 truncate">{f.title}</p>
                    <p className="text-xs text-zinc-600 mt-1 font-mono truncate">{f.resource}</p>
                  </div>
                  <span className="text-xs text-zinc-600 whitespace-nowrap">{f.age}d ago</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Top Attack Paths</h3>
            <button onClick={() => setActiveView("attack-paths")} className="text-xs text-blue-400 hover:text-blue-300">View all →</button>
          </div>
          <div className="space-y-3">
            {MOCK_ATTACK_PATHS.slice(0, 3).map(ap => (
              <div key={ap.id} className="p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50 hover:border-orange-500/30 transition-colors">
                <div className="flex items-center gap-2 mb-2">
                  <SeverityBadge severity={ap.severity} />
                  <span className="text-xs text-zinc-500">{ap.steps} steps • {ap.assets} assets</span>
                </div>
                <p className="text-sm text-zinc-200">{ap.name}</p>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-xs text-zinc-500">Blast radius: <span className="text-orange-400">{ap.blast}</span></span>
                  <span className="text-xs text-zinc-500">Probability: <span className={ap.probability === "High" ? "text-red-400" : "text-yellow-400"}>{ap.probability}</span></span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Compliance + CIEM Summary */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Compliance Overview</h3>
            <button onClick={() => setActiveView("compliance")} className="text-xs text-blue-400 hover:text-blue-300">View all →</button>
          </div>
          <div className="space-y-3">
            {MOCK_COMPLIANCE.slice(0, 5).map(c => (
              <div key={c.name} className="flex items-center gap-3">
                <span className="text-xs text-zinc-400 w-24 truncate">{c.name}</span>
                <div className="flex-1"><ProgressBar value={c.score} color={c.score >= 85 ? "#00e676" : c.score >= 70 ? "#ffc400" : "#ff1744"} /></div>
                <span className="text-xs font-mono text-zinc-300 w-10 text-right">{c.score}%</span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Identity Risk (CIEM)</h3>
            <button onClick={() => setActiveView("ciem")} className="text-xs text-blue-400 hover:text-blue-300">View all →</button>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 bg-zinc-800/50 rounded-lg text-center">
              <div className="text-xl font-bold text-orange-400">{MOCK_IDENTITIES.overPrivileged.toLocaleString()}</div>
              <div className="text-xs text-zinc-500">Over-Privileged</div>
            </div>
            <div className="p-3 bg-zinc-800/50 rounded-lg text-center">
              <div className="text-xl font-bold text-red-400">{MOCK_IDENTITIES.noMFA}</div>
              <div className="text-xs text-zinc-500">No MFA</div>
            </div>
            <div className="p-3 bg-zinc-800/50 rounded-lg text-center">
              <div className="text-xl font-bold text-yellow-400">{MOCK_IDENTITIES.inactive.toLocaleString()}</div>
              <div className="text-xs text-zinc-500">Inactive 90d+</div>
            </div>
            <div className="p-3 bg-zinc-800/50 rounded-lg text-center">
              <div className="text-xl font-bold text-red-400">{MOCK_IDENTITIES.toxicCombinations}</div>
              <div className="text-xs text-zinc-500">Toxic Combos</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );

  // ─── SECURITY GRAPH VIEW ───────────────────────────────────────────────────
  const GraphView = () => (
    <div className="space-y-6">
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Security Graph — Live Attack Path Visualization</h3>
          <div className="flex gap-2">
            <button className="px-3 py-1.5 text-xs bg-red-500/10 text-red-400 rounded-lg border border-red-500/20">Attack Paths</button>
            <button className="px-3 py-1.5 text-xs bg-zinc-800 text-zinc-400 rounded-lg border border-zinc-700">All Connections</button>
            <button className="px-3 py-1.5 text-xs bg-zinc-800 text-zinc-400 rounded-lg border border-zinc-700">Identity Map</button>
          </div>
        </div>
        <div className="h-[400px] rounded-lg overflow-hidden border border-zinc-800 bg-zinc-950">
          <SecurityGraph />
        </div>
        <div className="flex items-center gap-6 mt-4 text-xs text-zinc-500">
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Critical Risk</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> High Risk</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Standard</span>
          <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Secured</span>
          <span className="flex items-center gap-1"><span className="w-6 border-t border-dashed border-red-500" /> Attack Path</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <MetricCard icon={Share2} label="Graph Nodes" value="14,832" color="#448aff" subtitle="Assets, identities, configs" />
        <MetricCard icon={GitBranch} label="Graph Edges" value="47,291" color="#ffc400" subtitle="Relationships & permissions" />
        <MetricCard icon={Crosshair} label="Active Attack Paths" value="5" color="#ff1744" subtitle="2 critical, 2 high, 1 medium" />
      </div>
    </div>
  );

  // ─── CSPM VIEW ────────────────────────────────────────────────────────────
  const CSPMView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={AlertCircle} label="Total Misconfigs" value={342} change="-8%" changeType="up" color="#ff6d00" />
        <MetricCard icon={ShieldAlert} label="Critical" value={12} color="#ff1744" />
        <MetricCard icon={Clock} label="Mean Time to Remediate" value="4.2d" color="#ffc400" />
        <MetricCard icon={CheckCircle} label="Auto-Remediated (30d)" value={89} color="#00e676" />
      </div>

      {/* Findings Table */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-zinc-800 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider">Security Findings</h3>
          <div className="flex gap-2">
            {["All", ...CLOUD_PROVIDERS].map(p => (
              <button key={p} onClick={() => setSelectedProvider(p)}
                className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${selectedProvider === p ? "bg-blue-500/10 text-blue-400 border-blue-500/30" : "bg-zinc-800 text-zinc-500 border-zinc-700 hover:border-zinc-600"}`}>
                {p}
              </button>
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                <th className="px-4 py-3">ID</th>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Finding</th>
                <th className="px-4 py-3">Provider</th>
                <th className="px-4 py-3">Framework</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Age</th>
              </tr>
            </thead>
            <tbody>
              {filteredFindings.map(f => (
                <tr key={f.id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 cursor-pointer transition-colors" onClick={() => setSelectedFinding(f)}>
                  <td className="px-4 py-3 text-xs font-mono text-zinc-400">{f.id}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-zinc-200 max-w-md truncate">{f.title}</div>
                    <div className="text-xs text-zinc-600 font-mono truncate">{f.resource}</div>
                  </td>
                  <td className="px-4 py-3"><ProviderIcon provider={f.provider} size={12} /></td>
                  <td className="px-4 py-3 text-xs text-zinc-500">{f.framework}</td>
                  <td className="px-4 py-3"><StatusBadge status={f.status} /></td>
                  <td className="px-4 py-3 text-xs text-zinc-500">{f.age}d</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Cloud Breakdown */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {CLOUD_PROVIDERS.map(p => {
          const providerFindings = MOCK_FINDINGS.filter(f => f.provider === p);
          return (
            <div key={p} className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-3">
                <ProviderIcon provider={p} size={16} />
                <ScoreGauge score={p === "AWS" ? 68 : p === "Azure" ? 74 : 81} size={60} />
              </div>
              <div className="grid grid-cols-2 gap-2 mt-3">
                {Object.entries(SEVERITY).slice(0, 4).map(([key, val]) => (
                  <div key={key} className="text-center p-2 bg-zinc-800/50 rounded-lg">
                    <div className="text-lg font-bold" style={{ color: COLORS[val] }}>{providerFindings.filter(f => f.severity === val).length}</div>
                    <div className="text-[10px] text-zinc-500 uppercase">{key}</div>
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );

  // ─── CIEM VIEW ─────────────────────────────────────────────────────────────
  const CIEMView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-6 gap-4">
        <MetricCard icon={Users} label="Total Identities" value={MOCK_IDENTITIES.total} color="#448aff" />
        <MetricCard icon={UserX} label="Over-Privileged" value={MOCK_IDENTITIES.overPrivileged} change="-12%" changeType="up" color="#ff6d00" />
        <MetricCard icon={KeyRound} label="No MFA" value={MOCK_IDENTITIES.noMFA} color="#ff1744" />
        <MetricCard icon={Clock} label="Inactive 90d+" value={MOCK_IDENTITIES.inactive} color="#ffc400" />
        <MetricCard icon={Zap} label="Toxic Combinations" value={MOCK_IDENTITIES.toxicCombinations} color="#ff1744" />
        <MetricCard icon={Target} label="Permission Gap" value={`${MOCK_IDENTITIES.permissionGap}%`} color="#00e676" subtitle="Avg unused permissions" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Identity Risk Radar */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Identity Risk Matrix</h3>
          <IdentityRiskMatrix />
          <div className="flex items-center gap-4 mt-2 justify-center text-xs">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> Permissions</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500" /> Usage</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500" /> Risk</span>
          </div>
        </div>

        {/* Identity Distribution */}
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Identity Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={MOCK_IDENTITIES.breakdown} cx="50%" cy="50%" outerRadius={90} innerRadius={55} dataKey="value" stroke="none" paddingAngle={3}>
                {MOCK_IDENTITIES.breakdown.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap gap-3 justify-center mt-2">
            {MOCK_IDENTITIES.breakdown.map(b => (
              <span key={b.name} className="flex items-center gap-1 text-xs text-zinc-400">
                <span className="w-2 h-2 rounded-full" style={{ background: b.color }} />
                {b.name}: {b.value.toLocaleString()}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Entitlement Analysis */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Least Privilege Analysis — Top Over-Privileged Identities</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                <th className="px-4 py-3">Identity</th>
                <th className="px-4 py-3">Type</th>
                <th className="px-4 py-3">Provider</th>
                <th className="px-4 py-3">Granted</th>
                <th className="px-4 py-3">Used</th>
                <th className="px-4 py-3">Gap</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Recommendation</th>
              </tr>
            </thead>
            <tbody>
              {[
                { name: "LegacyAdmin", type: "Role", provider: "AWS", granted: 4821, used: 23, risk: "critical", rec: "Remove AdministratorAccess, scope to 23 used APIs" },
                { name: "deploy@prod.iam", type: "Service Acct", provider: "GCP", granted: 2134, used: 156, risk: "high", rec: "Reduce to custom role with 156 permissions" },
                { name: "CI-CD-Pipeline", type: "App Registration", provider: "Azure", granted: 1876, used: 89, risk: "high", rec: "Create scoped custom role for deployment only" },
                { name: "data-team@corp.com", type: "Group", provider: "AWS", granted: 987, used: 234, risk: "medium", rec: "Split into read-only and write groups" },
                { name: "monitoring-svc", type: "Service Acct", provider: "GCP", granted: 456, used: 312, risk: "low", rec: "Minor optimization: remove 144 unused permissions" },
              ].map((id, i) => (
                <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                  <td className="px-4 py-3 text-sm text-zinc-200 font-mono">{id.name}</td>
                  <td className="px-4 py-3 text-xs text-zinc-400">{id.type}</td>
                  <td className="px-4 py-3"><ProviderIcon provider={id.provider} size={12} /></td>
                  <td className="px-4 py-3 text-sm text-zinc-300">{id.granted.toLocaleString()}</td>
                  <td className="px-4 py-3 text-sm text-emerald-400">{id.used}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ProgressBar value={id.used} max={id.granted} color={COLORS[id.risk]} />
                      <span className="text-xs text-zinc-500 w-12">{Math.round((1 - id.used / id.granted) * 100)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3"><SeverityBadge severity={id.risk} /></td>
                  <td className="px-4 py-3 text-xs text-zinc-500 max-w-xs truncate">{id.rec}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Toxic Combinations */}
      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">⚡ Toxic Combinations Detected</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { combo: "Admin Access + No MFA + External Access", count: 3, severity: "critical", desc: "IAM roles with full admin, no MFA requirement, and cross-account trust" },
            { combo: "S3 Full Access + Public Bucket + Sensitive Tags", count: 7, severity: "critical", desc: "Identities with S3:* on buckets tagged as containing PII/PHI" },
            { combo: "EC2 Admin + SSM Access + No Logging", count: 12, severity: "high", desc: "Can launch instances and execute commands without CloudTrail" },
            { combo: "Lambda Invoke + IAM PassRole + No Boundary", count: 8, severity: "high", desc: "Can invoke functions that assume any role without permission boundary" },
          ].map((tc, i) => (
            <div key={i} className="p-4 bg-zinc-800/50 rounded-lg border border-zinc-700/50 hover:border-red-500/20 transition-colors">
              <div className="flex items-center gap-2 mb-2">
                <SeverityBadge severity={tc.severity} />
                <span className="text-xs text-zinc-500">{tc.count} identities</span>
              </div>
              <p className="text-sm text-zinc-200 font-medium">{tc.combo}</p>
              <p className="text-xs text-zinc-500 mt-1">{tc.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ─── CWPP VIEW ─────────────────────────────────────────────────────────────
  const CWPPView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={Server} label="Workloads Scanned" value="9,247" color="#448aff" />
        <MetricCard icon={ShieldCheck} label="Protected" value="8,891" color="#00e676" subtitle="96.2% coverage" />
        <MetricCard icon={Bug} label="Runtime Threats" value={23} color="#ff1744" change="+3" changeType="down" />
        <MetricCard icon={FileWarning} label="Malware Detected" value={7} color="#ff6d00" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Workload Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={[
              { name: "EC2", critical: 8, high: 23, medium: 45, low: 123 },
              { name: "ECS", critical: 3, high: 12, medium: 34, low: 89 },
              { name: "Lambda", critical: 1, high: 8, medium: 56, low: 234 },
              { name: "VMs", critical: 5, high: 19, medium: 38, low: 112 },
              { name: "AKS", critical: 7, high: 15, medium: 28, low: 67 },
              { name: "GCE", critical: 4, high: 11, medium: 31, low: 98 },
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="name" tick={{ fill: "#71717a", fontSize: 11 }} />
              <YAxis tick={{ fill: "#71717a", fontSize: 11 }} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="critical" stackId="a" fill="#ff1744" radius={[0, 0, 0, 0]} />
              <Bar dataKey="high" stackId="a" fill="#ff6d00" />
              <Bar dataKey="medium" stackId="a" fill="#ffc400" />
              <Bar dataKey="low" stackId="a" fill="#00e676" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Runtime Protection Events (24h)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={Array.from({ length: 24 }, (_, i) => ({
              hour: `${i}:00`,
              blocked: Math.floor(Math.random() * 15) + 2,
              detected: Math.floor(Math.random() * 8) + 1,
              allowed: Math.floor(Math.random() * 50) + 30,
            }))}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis dataKey="hour" tick={{ fill: "#71717a", fontSize: 10 }} interval={3} />
              <YAxis tick={{ fill: "#71717a", fontSize: 10 }} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
              <Line type="monotone" dataKey="blocked" stroke="#ff1744" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="detected" stroke="#ffc400" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );

  // ─── VULNERABILITIES VIEW ──────────────────────────────────────────────────
  const VulnsView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <MetricCard icon={Bug} label="Total CVEs" value={MOCK_VULNS.total} color="#ffc400" />
        <MetricCard icon={AlertCircle} label="Critical" value={MOCK_VULNS.critical} color="#ff1744" />
        <MetricCard icon={AlertTriangle} label="High" value={MOCK_VULNS.high} color="#ff6d00" />
        <MetricCard icon={Info} label="Exploitable" value={34} color="#ff1744" subtitle="Known exploits in wild" />
        <MetricCard icon={Clock} label="MTTR" value="3.8d" color="#448aff" subtitle="Mean time to remediate" />
      </div>

      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Top Critical CVEs</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                <th className="px-4 py-3">CVE ID</th>
                <th className="px-4 py-3">CVSS</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Affected</th>
                <th className="px-4 py-3">Exploited</th>
                <th className="px-4 py-3">Fix Available</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_VULNS.topCVEs.map(v => (
                <tr key={v.id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                  <td className="px-4 py-3 text-sm font-mono text-blue-400">{v.id}</td>
                  <td className="px-4 py-3"><span className={`px-2 py-0.5 rounded text-xs font-bold ${v.score >= 9 ? "bg-red-500/15 text-red-400" : "bg-orange-500/15 text-orange-400"}`}>{v.score}</span></td>
                  <td className="px-4 py-3 text-sm text-zinc-300">{v.title}</td>
                  <td className="px-4 py-3 text-sm text-zinc-400">{v.affected} assets</td>
                  <td className="px-4 py-3">{v.exploited ? <span className="text-xs text-red-400 flex items-center gap-1"><Zap size={12} />Yes</span> : <span className="text-xs text-zinc-600">No</span>}</td>
                  <td className="px-4 py-3"><Check size={14} className="text-emerald-400" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Vulnerability Trend (30 Days)</h3>
        <ResponsiveContainer width="100%" height={250}>
          <AreaChart data={MOCK_VULNS.trend}>
            <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
            <XAxis dataKey="date" tick={{ fill: "#71717a", fontSize: 10 }} interval={4} />
            <YAxis tick={{ fill: "#71717a", fontSize: 10 }} />
            <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
            <Area type="monotone" dataKey="value" stroke="#ffc400" fill="#ffc40020" strokeWidth={2} />
            <Area type="monotone" dataKey="resolved" stroke="#00e676" fill="#00e67620" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );

  // ─── CONTAINERS VIEW ───────────────────────────────────────────────────────
  const ContainersView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={Box} label="Clusters" value={MOCK_CONTAINERS.clusters} color="#448aff" />
        <MetricCard icon={Layers} label="Running Pods" value={MOCK_CONTAINERS.pods} color="#00e676" />
        <MetricCard icon={Scan} label="Vulnerable Images" value={MOCK_CONTAINERS.vulnerableImages} color="#ff6d00" />
        <MetricCard icon={ShieldAlert} label="Privileged Pods" value={MOCK_CONTAINERS.privilegedPods} color="#ff1744" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Container Security Posture</h3>
          <div className="space-y-4">
            {[
              { check: "Image vulnerability scanning", status: "pass", coverage: "94%" },
              { check: "Runtime threat detection", status: "pass", coverage: "89%" },
              { check: "Network policy enforcement", status: "warn", coverage: "72%" },
              { check: "Pod security standards", status: "warn", coverage: "81%" },
              { check: "Secret management", status: "pass", coverage: "96%" },
              { check: "Registry scanning", status: "pass", coverage: "100%" },
              { check: "Admission controller", status: "fail", coverage: "45%" },
              { check: "Resource limits", status: "warn", coverage: "68%" },
            ].map((c, i) => (
              <div key={i} className="flex items-center gap-3">
                {c.status === "pass" ? <CheckCircle size={14} className="text-emerald-400" /> : c.status === "warn" ? <AlertTriangle size={14} className="text-yellow-400" /> : <XCircle size={14} className="text-red-400" />}
                <span className="text-sm text-zinc-300 flex-1">{c.check}</span>
                <span className="text-xs text-zinc-500">{c.coverage}</span>
                <div className="w-24"><ProgressBar value={parseInt(c.coverage)} color={c.status === "pass" ? "#00e676" : c.status === "warn" ? "#ffc400" : "#ff1744"} /></div>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Image Risk Summary</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart layout="vertical" data={[
              { name: "prod/api-server", critical: 3, high: 12, medium: 34 },
              { name: "prod/web-frontend", critical: 0, high: 5, medium: 23 },
              { name: "prod/worker", critical: 7, high: 8, medium: 15 },
              { name: "prod/auth-svc", critical: 1, high: 3, medium: 12 },
              { name: "prod/data-pipeline", critical: 2, high: 9, medium: 28 },
              { name: "base/ubuntu-22.04", critical: 0, high: 2, medium: 8 },
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
              <XAxis type="number" tick={{ fill: "#71717a", fontSize: 10 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: "#71717a", fontSize: 10 }} width={130} />
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="critical" stackId="a" fill="#ff1744" />
              <Bar dataKey="high" stackId="a" fill="#ff6d00" />
              <Bar dataKey="medium" stackId="a" fill="#ffc400" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );

  // ─── ATTACK PATHS VIEW ─────────────────────────────────────────────────────
  const AttackPathsView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={Crosshair} label="Total Attack Paths" value={MOCK_ATTACK_PATHS.length} color="#ff1744" />
        <MetricCard icon={AlertCircle} label="Critical Paths" value={2} color="#ff1744" />
        <MetricCard icon={Target} label="Avg Blast Radius" value="4.2k" color="#ff6d00" subtitle="assets affected" />
        <MetricCard icon={ShieldCheck} label="Paths Remediated (30d)" value={12} color="#00e676" />
      </div>

      <div className="space-y-4">
        {MOCK_ATTACK_PATHS.map(ap => (
          <div key={ap.id} className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6 hover:border-zinc-700 transition-colors">
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={ap.severity} />
                  <span className="text-xs text-zinc-500 font-mono">{ap.id}</span>
                </div>
                <h4 className="text-lg text-zinc-200 font-medium">{ap.name}</h4>
              </div>
              <div className="text-right">
                <div className="text-xs text-zinc-500">Blast Radius</div>
                <div className="text-sm text-orange-400 font-semibold">{ap.blast}</div>
              </div>
            </div>
            <AttackPathDiagram path={ap} />
            <div className="flex items-center gap-6 mt-3 text-xs text-zinc-500">
              <span>{ap.steps} steps</span>
              <span>{ap.assets} assets involved</span>
              <span>Probability: <span className={ap.probability === "High" ? "text-red-400" : "text-yellow-400"}>{ap.probability}</span></span>
              <button className="ml-auto text-blue-400 hover:text-blue-300">View Details →</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  // ─── COMPLIANCE VIEW ───────────────────────────────────────────────────────
  const ComplianceView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        {MOCK_COMPLIANCE.slice(0, 5).map(c => (
          <div key={c.name} className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5 text-center">
            <ScoreGauge score={c.score} size={80} />
            <div className="text-sm font-medium text-zinc-300 mt-2">{c.name}</div>
            <div className="text-xs text-zinc-600">{c.passing}/{c.controls} controls</div>
          </div>
        ))}
      </div>

      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">All Frameworks</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                <th className="px-4 py-3">Framework</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Progress</th>
                <th className="px-4 py-3">Passing</th>
                <th className="px-4 py-3">Failing</th>
                <th className="px-4 py-3">Scope</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_COMPLIANCE.map(c => (
                <tr key={c.name} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                  <td className="px-4 py-3 text-sm text-zinc-200 font-medium">{c.name}</td>
                  <td className="px-4 py-3">
                    <span className={`text-sm font-bold ${c.score >= 85 ? "text-emerald-400" : c.score >= 70 ? "text-yellow-400" : "text-red-400"}`}>{c.score}%</span>
                  </td>
                  <td className="px-4 py-3 w-40"><ProgressBar value={c.score} color={c.score >= 85 ? "#00e676" : c.score >= 70 ? "#ffc400" : "#ff1744"} /></td>
                  <td className="px-4 py-3 text-sm text-emerald-400">{c.passing}</td>
                  <td className="px-4 py-3 text-sm text-red-400">{c.failing}</td>
                  <td className="px-4 py-3 text-xs text-zinc-500">{c.provider}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  // ─── IaC SECURITY VIEW ─────────────────────────────────────────────────────
  const IaCView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={GitBranch} label="Repos Scanned" value={MOCK_IAC.repos} color="#448aff" />
        <MetricCard icon={Scan} label="Total Scans" value={MOCK_IAC.totalScans} color="#00e676" />
        <MetricCard icon={FileWarning} label="IaC Findings" value={MOCK_IAC.findings} color="#ff6d00" />
        <MetricCard icon={XCircle} label="Blocked Deploys" value={MOCK_IAC.blockedDeploys} color="#ff1744" subtitle="Policy violations caught" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">IaC Framework Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie data={[
                { name: "Terraform", value: 45 },
                { name: "CloudFormation", value: 25 },
                { name: "Helm Charts", value: 15 },
                { name: "ARM Templates", value: 10 },
                { name: "Pulumi", value: 5 },
              ]} cx="50%" cy="50%" outerRadius={90} innerRadius={50} dataKey="value" stroke="none" paddingAngle={3}>
                {["#448aff", "#ff9900", "#00e676", "#0078d4", "#ffc400"].map((c, i) => <Cell key={i} fill={c} />)}
              </Pie>
              <Tooltip contentStyle={{ background: "#18181b", border: "1px solid #27272a", borderRadius: 8, fontSize: 12 }} />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
          <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Drift Detection</h3>
          <div className="text-center py-4">
            <div className="text-4xl font-bold text-orange-400 mb-1">{MOCK_IAC.driftDetected}</div>
            <div className="text-sm text-zinc-500">Resources with Configuration Drift</div>
          </div>
          <div className="space-y-3 mt-4">
            {[
              { resource: "aws_security_group.allow_ssh", drift: "Ingress rule added manually", severity: "high" },
              { resource: "azurerm_storage_account.logs", drift: "Public access enabled", severity: "critical" },
              { resource: "google_compute_firewall.web", drift: "Source ranges modified", severity: "medium" },
            ].map((d, i) => (
              <div key={i} className="p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-zinc-300">{d.resource}</span>
                  <SeverityBadge severity={d.severity} />
                </div>
                <p className="text-xs text-zinc-500 mt-1">{d.drift}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // ─── ASSET INVENTORY VIEW ──────────────────────────────────────────────────
  const InventoryView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
        {CLOUD_PROVIDERS.map(p => (
          <div key={p} className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-5">
            <ProviderIcon provider={p} size={16} />
            <div className="text-2xl font-bold text-white mt-2">{MOCK_ASSETS.breakdown.filter(a => a.provider === p).reduce((s, a) => s + a.count, 0).toLocaleString()}</div>
            <div className="text-xs text-zinc-500">assets</div>
          </div>
        ))}
      </div>

      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Asset Inventory</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-left">
            <thead>
              <tr className="text-xs text-zinc-500 uppercase tracking-wider border-b border-zinc-800">
                <th className="px-4 py-3">Resource Type</th>
                <th className="px-4 py-3">Provider</th>
                <th className="px-4 py-3">Count</th>
                <th className="px-4 py-3">At Risk</th>
                <th className="px-4 py-3">Risk %</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_ASSETS.breakdown.map((a, i) => (
                <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                  <td className="px-4 py-3 text-sm text-zinc-200">{a.name}</td>
                  <td className="px-4 py-3"><ProviderIcon provider={a.provider} size={12} /></td>
                  <td className="px-4 py-3 text-sm text-zinc-300">{a.count.toLocaleString()}</td>
                  <td className="px-4 py-3 text-sm text-orange-400">{Math.round(a.count * a.risk / 100)}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <ProgressBar value={a.risk} color={a.risk > 25 ? "#ff1744" : a.risk > 15 ? "#ff6d00" : "#00e676"} />
                      <span className="text-xs text-zinc-500 w-8">{a.risk}%</span>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );

  // ─── ALERTS VIEW ───────────────────────────────────────────────────────────
  const AlertsView = () => (
    <div className="space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <MetricCard icon={Bell} label="Active Alerts" value={47} color="#ff1744" />
        <MetricCard icon={Clock} label="Avg Response Time" value="12m" color="#448aff" />
        <MetricCard icon={Check} label="Resolved Today" value={23} color="#00e676" />
        <MetricCard icon={Users} label="Assigned" value={31} color="#ffc400" />
      </div>

      <div className="bg-zinc-900/80 border border-zinc-800 rounded-xl p-6">
        <h3 className="text-sm font-semibold text-zinc-400 uppercase tracking-wider mb-4">Recent Alerts</h3>
        <div className="space-y-3">
          {[
            { title: "Critical: Public S3 bucket with PII detected", time: "2 min ago", severity: "critical", source: "CSPM", assignee: "Security Team" },
            { title: "Admin role assumed from unknown IP", time: "8 min ago", severity: "critical", source: "CIEM", assignee: "SOC Analyst" },
            { title: "Container escape attempt blocked", time: "15 min ago", severity: "high", source: "CWPP", assignee: "Platform Team" },
            { title: "New critical CVE affects 34 production assets", time: "1h ago", severity: "high", source: "Vuln Mgmt", assignee: "Patch Team" },
            { title: "Terraform drift: security group modified", time: "2h ago", severity: "medium", source: "IaC", assignee: "DevOps" },
            { title: "Unused service account key rotation overdue", time: "3h ago", severity: "medium", source: "CIEM", assignee: "IAM Team" },
            { title: "Compliance check failed: encryption at rest", time: "4h ago", severity: "high", source: "Compliance", assignee: "Security Team" },
          ].map((a, i) => (
            <div key={i} className="p-4 bg-zinc-800/50 rounded-lg border border-zinc-700/50 hover:border-zinc-600/50 transition-colors flex items-start gap-3">
              <div className="mt-0.5">
                {a.severity === "critical" ? <AlertCircle size={16} className="text-red-400" /> : a.severity === "high" ? <AlertTriangle size={16} className="text-orange-400" /> : <Info size={16} className="text-yellow-400" />}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm text-zinc-200">{a.title}</p>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-xs text-zinc-500">{a.time}</span>
                  <span className="text-xs text-zinc-600">•</span>
                  <span className="text-xs text-zinc-500">{a.source}</span>
                  <span className="text-xs text-zinc-600">•</span>
                  <span className="text-xs text-zinc-500">{a.assignee}</span>
                </div>
              </div>
              <SeverityBadge severity={a.severity} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // ─── FINDING DETAIL MODAL ──────────────────────────────────────────────────
  const FindingModal = ({ finding, onClose }) => (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-zinc-900 border border-zinc-700 rounded-2xl max-w-2xl w-full max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="p-6 border-b border-zinc-800 flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <SeverityBadge severity={finding.severity} />
              <StatusBadge status={finding.status} />
              <ProviderIcon provider={finding.provider} size={12} />
            </div>
            <h3 className="text-lg font-semibold text-white">{finding.title}</h3>
            <p className="text-xs font-mono text-zinc-500 mt-1">{finding.id}</p>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-zinc-800 rounded-lg transition-colors"><X size={18} className="text-zinc-400" /></button>
        </div>
        <div className="p-6 space-y-4">
          <div>
            <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Resource</h4>
            <p className="text-sm font-mono text-zinc-300 bg-zinc-800/50 p-3 rounded-lg break-all">{finding.resource}</p>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Category</h4>
              <p className="text-sm text-zinc-300">{finding.category}</p>
            </div>
            <div>
              <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Framework</h4>
              <p className="text-sm text-zinc-300">{finding.framework}</p>
            </div>
            <div>
              <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Age</h4>
              <p className="text-sm text-zinc-300">{finding.age} days</p>
            </div>
            <div>
              <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Attack Path</h4>
              <p className="text-sm text-zinc-300">{finding.attackPath ? "⚡ Part of active attack path" : "Not in attack path"}</p>
            </div>
          </div>
          <div>
            <h4 className="text-xs text-zinc-500 uppercase tracking-wider mb-2">Remediation</h4>
            <div className="text-sm text-zinc-400 bg-zinc-800/50 p-4 rounded-lg space-y-2">
              <p>1. Review the resource configuration immediately</p>
              <p>2. Apply the auto-generated remediation policy</p>
              <p>3. Validate fix with compliance re-scan</p>
              <p>4. Set up preventive guardrail to block recurrence</p>
            </div>
          </div>
          <div className="flex gap-3">
            <button className="flex-1 py-2.5 bg-blue-500 hover:bg-blue-600 text-white text-sm font-medium rounded-lg transition-colors">Auto-Remediate</button>
            <button className="flex-1 py-2.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-sm font-medium rounded-lg border border-zinc-700 transition-colors">Create Ticket</button>
            <button className="py-2.5 px-4 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-sm rounded-lg border border-zinc-700 transition-colors">Suppress</button>
          </div>
        </div>
      </div>
    </div>
  );

  // ─── VIEW ROUTER ───────────────────────────────────────────────────────────
  const viewMap = {
    overview: OverviewView,
    graph: GraphView,
    cspm: CSPMView,
    ciem: CIEMView,
    cwpp: CWPPView,
    vulns: VulnsView,
    containers: ContainersView,
    "attack-paths": AttackPathsView,
    compliance: ComplianceView,
    iac: IaCView,
    inventory: InventoryView,
    alerts: AlertsView,
  };
  const ActiveViewComponent = viewMap[activeView] || OverviewView;

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex" style={{ fontFamily: "'JetBrains Mono', 'SF Mono', 'Fira Code', monospace" }}>
      {/* Import fonts */}
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Space+Grotesk:wght@300;400;500;600;700&display=swap');
        body { font-family: 'Space Grotesk', sans-serif; }
        * { font-family: 'Space Grotesk', sans-serif; }
        code, .font-mono { font-family: 'JetBrains Mono', monospace; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #09090b; }
        ::-webkit-scrollbar-thumb { background: #27272a; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #3f3f46; }
      `}</style>

      {/* Sidebar */}
      <aside className={`${sidebarCollapsed ? "w-16" : "w-60"} bg-zinc-950 border-r border-zinc-800/50 flex flex-col transition-all duration-300 flex-shrink-0`}>
        {/* Logo */}
        <div className="p-4 border-b border-zinc-800/50">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center flex-shrink-0">
              <Shield size={16} className="text-white" />
            </div>
            {!sidebarCollapsed && (
              <div>
                <div className="text-sm font-bold text-white tracking-tight">CloudFortress</div>
                <div className="text-[10px] text-zinc-600 uppercase tracking-widest">CNAPP + CIEM</div>
              </div>
            )}
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 py-3 overflow-y-auto">
          {NAV_ITEMS.map(item => (
            <button key={item.id} onClick={() => setActiveView(item.id)}
              className={`w-full flex items-center gap-3 px-4 py-2.5 text-sm transition-all duration-200 ${
                activeView === item.id
                  ? "text-white bg-zinc-800/60 border-r-2 border-blue-500"
                  : "text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900"
              }`}>
              <item.icon size={16} className="flex-shrink-0" />
              {!sidebarCollapsed && <span>{item.label}</span>}
            </button>
          ))}
        </nav>

        {/* Collapse */}
        <div className="p-3 border-t border-zinc-800/50">
          <button onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            className="w-full flex items-center justify-center gap-2 p-2 text-xs text-zinc-600 hover:text-zinc-400 rounded-lg hover:bg-zinc-900 transition-colors">
            {sidebarCollapsed ? <ChevronRight size={14} /> : <><ChevronDown size={14} /> <span>Collapse</span></>}
          </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col min-w-0">
        {/* Top Bar */}
        <header className="h-14 border-b border-zinc-800/50 flex items-center justify-between px-6 bg-zinc-950/80 backdrop-blur-xl flex-shrink-0">
          <div className="flex items-center gap-4">
            <h1 className="text-base font-semibold text-zinc-200">{NAV_ITEMS.find(n => n.id === activeView)?.label || "Overview"}</h1>
            <div className="h-4 w-px bg-zinc-800" />
            <div className="flex items-center gap-1.5 text-xs text-zinc-500">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
              Last scan: 4 min ago
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="relative">
              <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search assets, findings, CVEs..."
                className="w-64 pl-9 pr-3 py-1.5 text-sm bg-zinc-900 border border-zinc-800 rounded-lg text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-zinc-700" />
            </div>
            <button className="relative p-2 hover:bg-zinc-900 rounded-lg transition-colors" onClick={() => setShowNotifications(!showNotifications)}>
              <Bell size={16} className="text-zinc-400" />
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500" />
            </button>
            <button className="p-2 hover:bg-zinc-900 rounded-lg transition-colors">
              <RefreshCw size={16} className="text-zinc-400" />
            </button>
            <button className="p-2 hover:bg-zinc-900 rounded-lg transition-colors">
              <Settings size={16} className="text-zinc-400" />
            </button>
            <div className="w-8 h-8 rounded-full bg-gradient-to-br from-blue-500 to-cyan-500 flex items-center justify-center text-xs font-bold text-white">
              MK
            </div>
          </div>
        </header>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          <ActiveViewComponent />
        </div>
      </main>

      {/* Finding Detail Modal */}
      {selectedFinding && <FindingModal finding={selectedFinding} onClose={() => setSelectedFinding(null)} />}
    </div>
  );
}
