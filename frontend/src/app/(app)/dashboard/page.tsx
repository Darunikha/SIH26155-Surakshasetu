"use client";

import { useQuery } from "@tanstack/react-query";
import { dashboardApi } from "@/lib/api";
import { StatCard } from "@/components/ui/stat-card";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { LoadingBlock, ErrorBlock } from "@/components/ui/misc";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#f25623",
  MEDIUM: "#eab308",
  LOW: "#4d4d4d",
};

const CHART_GRID = "#dedede";
const CHART_AXIS = "#4d4d4d";
const CHART_TOOLTIP_STYLE = { background: "#ffffff", border: "1px solid #dedede", color: "#171717", fontSize: 12 };

export default function DashboardPage() {
  const summaryQuery = useQuery({ queryKey: ["dashboard-summary"], queryFn: () => dashboardApi.summary() });
  const trendQuery = useQuery({ queryKey: ["risk-trend"], queryFn: () => dashboardApi.riskTrend() });

  if (summaryQuery.isLoading) return <LoadingBlock />;
  if (summaryQuery.isError) return <ErrorBlock message={(summaryQuery.error as Error).message} />;

  const s = summaryQuery.data!;
  const severityData = Object.entries(s.findings_by_severity).map(([severity, count]) => ({ severity, count }));
  const frameworkData = Object.entries(s.compliance_by_framework).map(([framework, coverage]) => ({ framework, coverage }));
  const trendData = (trendQuery.data || []).map((p) => ({
    date: new Date(p.created_at).toLocaleDateString(),
    risk: p.risk_score,
    compliance: p.compliance_score,
  }));

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-semibold">Dashboard</h1>
        <p className="text-sm text-muted">Live figures aggregated from MongoDB — nothing here is hard-coded.</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Devices" value={s.total_devices} />
        <StatCard label="Total Configurations" value={s.total_configurations} />
        <StatCard label="Total Audits" value={s.total_audits} />
        <StatCard
          label="Avg. Compliance"
          value={s.average_compliance_percent !== null ? `${s.average_compliance_percent}%` : "N/A"}
          accent={s.average_compliance_percent !== null && s.average_compliance_percent >= 70 ? "success" : "warning"}
        />
        <StatCard
          label="Avg. Risk Score"
          value={s.average_risk_score ?? "N/A"}
          accent={s.average_risk_score !== null && s.average_risk_score >= 60 ? "danger" : "primary"}
        />
        <StatCard label="Potential Attack Paths" value={s.potential_attack_paths} accent="warning" />
        <StatCard
          label="Remediation Progress"
          value={s.remediation_progress_percent !== null ? `${s.remediation_progress_percent}%` : "N/A"}
          accent="success"
        />
        <StatCard
          label="Blockchain Verification Rate"
          value={s.blockchain_verification_rate_percent !== null ? `${s.blockchain_verification_rate_percent}%` : "N/A"}
          accent="primary"
        />
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Findings by Severity</CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            {severityData.every((d) => d.count === 0) ? (
              <p className="text-sm text-muted">No findings recorded yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
                  <XAxis dataKey="severity" stroke={CHART_AXIS} fontSize={12} />
                  <YAxis stroke={CHART_AXIS} fontSize={12} allowDecimals={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="count">
                    {severityData.map((d) => (
                      <Cell key={d.severity} fill={SEVERITY_COLORS[d.severity]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Compliance Coverage by Framework</CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            {frameworkData.length === 0 ? (
              <p className="text-sm text-muted">No completed scans yet.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={frameworkData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
                  <XAxis type="number" domain={[0, 100]} stroke={CHART_AXIS} fontSize={12} />
                  <YAxis type="category" dataKey="framework" stroke={CHART_AXIS} fontSize={11} width={90} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Bar dataKey="coverage" fill="#f25623" />
                </BarChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card className="md:col-span-2">
          <CardHeader>
            <CardTitle>Risk &amp; Compliance Trend</CardTitle>
          </CardHeader>
          <CardContent className="h-64">
            {trendData.length === 0 ? (
              <p className="text-sm text-muted">Run scans to see a trend over time.</p>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trendData}>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART_GRID} />
                  <XAxis dataKey="date" stroke={CHART_AXIS} fontSize={12} />
                  <YAxis stroke={CHART_AXIS} fontSize={12} domain={[0, 100]} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Line type="monotone" dataKey="risk" stroke="#ef4444" name="Risk" strokeWidth={2} dot={false} />
                  <Line type="monotone" dataKey="compliance" stroke="#22c55e" name="Compliance %" strokeWidth={2} dot={false} />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
