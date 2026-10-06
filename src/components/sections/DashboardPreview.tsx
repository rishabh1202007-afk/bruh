import { Shield, Home, AlertTriangle, Bell, Network, Briefcase, FileSearch, FileText, Settings, ChevronDown, BellRing, User, ArrowUpRight, Search, MessageSquare, Send, BrainCircuit } from "lucide-react";

export function DashboardPreview() {
  return (
    <section className="py-24 bg-bg-main overflow-hidden">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-4">
            See the Full <span className="text-gradient">Investigation Picture</span>
          </h2>
          <p className="text-lg text-text-secondary">
            Experience a SOC interface designed for speed and clarity, natively bridging the gap between raw data and actionable response.
          </p>
        </div>

        {/* Dashboard Container - Forced Dark Theme Palette */}
        <div className="w-full rounded-2xl overflow-hidden shadow-2xl border border-border-subtle/50 text-[#F8FAFC] font-sans flex flex-col" style={{ backgroundColor: "#081B2B", height: "800px" }}>
          
          {/* Topbar */}
          <div className="h-14 flex items-center justify-between px-4" style={{ backgroundColor: "#111827", borderBottom: "1px solid #1F2937" }}>
            <div className="flex items-center gap-2 text-[#14B8A6]">
              <Shield className="w-6 h-6" />
              <span className="font-bold text-lg text-[#F8FAFC]">SentinelMesh</span>
            </div>
            
            <div className="flex-1 max-w-2xl mx-8">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm" style={{ backgroundColor: "#1F2937", border: "1px solid #334155" }}>
                <Search className="w-4 h-4 text-[#94A3B8]" />
                <span className="text-[#94A3B8]">Search incidents, alerts, assets, users...</span>
              </div>
            </div>

            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 text-sm" style={{ backgroundColor: "#1F2937", padding: "4px 12px", borderRadius: "6px" }}>
                <span className="text-[#94A3B8]">Last 24 hours</span>
                <ChevronDown className="w-4 h-4 text-[#94A3B8]" />
              </div>
              <div className="relative">
                <BellRing className="w-5 h-5 text-[#94A3B8]" />
                <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full" style={{ backgroundColor: "#EF4444" }} />
              </div>
              <div className="flex items-center gap-2 pl-2 border-l" style={{ borderColor: "#334155" }}>
                <div className="w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold" style={{ backgroundColor: "#3B82F6" }}>
                  SS
                </div>
                <div className="hidden sm:block text-xs">
                  <div className="font-semibold text-[#F8FAFC]">Shruti Singh</div>
                  <div className="text-[#94A3B8]">Analyst</div>
                </div>
              </div>
            </div>
          </div>

          <div className="flex-1 flex overflow-hidden">
            {/* Sidebar */}
            <div className="w-64 flex-shrink-0 flex flex-col p-4 gap-1 overflow-y-auto" style={{ backgroundColor: "#081B2B", borderRight: "1px solid #1F2937" }}>
              <SidebarItem icon={Home} label="Overview" active />
              <SidebarItem icon={AlertTriangle} label="Incidents" />
              <SidebarItem icon={Bell} label="Alerts" />
              <SidebarItem icon={Network} label="Attack Graph" />
              <SidebarItem icon={MessageSquare} label="AI Investigator" />
              <SidebarItem icon={Briefcase} label="Cases" />
              <SidebarItem icon={FileSearch} label="Evidence" />
              <SidebarItem icon={FileText} label="Reports" />
              <div className="mt-auto" />
              <SidebarItem icon={Settings} label="Settings" />
              
              <div className="mt-4 p-3 rounded-xl flex items-center gap-3 text-xs" style={{ backgroundColor: "#111827", border: "1px solid #1F2937" }}>
                 <div className="w-2 h-2 rounded-full" style={{ backgroundColor: "#22C55E" }} />
                 <div>
                   <div className="text-[#F8FAFC]">System Online</div>
                   <div className="text-[#94A3B8]">Last updated: 2 min ago</div>
                 </div>
              </div>
            </div>

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col p-6 overflow-y-auto gap-6" style={{ backgroundColor: "#081B2B" }}>
              <div>
                <h1 className="text-2xl font-bold text-[#F8FAFC] mb-1">SOC Overview</h1>
                <p className="text-sm text-[#94A3B8]">Real-time security posture and incident intelligence</p>
              </div>

              {/* KPI Cards */}
              <div className="grid grid-cols-5 gap-4">
                <KPICard title="Critical Incidents" value="8" trend="+33%" color="#EF4444" />
                <KPICard title="High Risk Incidents" value="21" trend="+18%" color="#F59E0B" />
                <KPICard title="Total Alerts" value="12.4K" trend="↓ 12%" color="#3B82F6" />
                <KPICard title="Open Incidents" value="34" trend="+9%" color="#22C55E" />
                <KPICard title="Affected Assets" value="18" trend="+6%" color="#8B5CF6" />
              </div>

              {/* Middle Row: Charts */}
              <div className="grid grid-cols-3 gap-4 h-64">
                {/* Trend Chart Mock */}
                <div className="col-span-1 rounded-xl p-4 flex flex-col" style={{ backgroundColor: "#111827", border: "1px solid #1F2937" }}>
                  <div className="text-sm font-semibold mb-4 text-[#F8FAFC]">Incident & Alert Trend</div>
                  <div className="flex-1 relative border-l border-b flex items-end" style={{ borderColor: "#334155" }}>
                     {/* SVG Mock of a line chart */}
                     <svg className="w-full h-full absolute inset-0" viewBox="0 0 100 100" preserveAspectRatio="none">
                       <path d="M0,80 L20,70 L40,85 L60,40 L80,50 L100,20" fill="none" stroke="#3B82F6" strokeWidth="2" />
                       <path d="M0,90 L20,85 L40,95 L60,70 L80,80 L100,60" fill="none" stroke="#14B8A6" strokeWidth="2" />
                     </svg>
                  </div>
                </div>

                {/* Risk Distribution Mock */}
                <div className="col-span-1 rounded-xl p-4 flex flex-col" style={{ backgroundColor: "#111827", border: "1px solid #1F2937" }}>
                  <div className="text-sm font-semibold mb-4 text-[#F8FAFC]">Risk Distribution</div>
                  <div className="flex-1 flex items-center justify-center relative">
                    {/* Donut chart mock */}
                    <div className="w-32 h-32 rounded-full border-[12px] flex items-center justify-center relative" style={{ borderColor: "#1F2937" }}>
                      <div className="absolute inset-[-12px] rounded-full border-[12px] border-transparent border-t-[#EF4444] border-r-[#F59E0B] border-b-[#22C55E] border-l-[#3B82F6] transform rotate-45" />
                      <div className="text-center">
                        <div className="text-2xl font-bold">34</div>
                        <div className="text-[10px] text-[#94A3B8]">Incidents</div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Top Affected Assets Mock */}
                <div className="col-span-1 rounded-xl p-4 flex flex-col" style={{ backgroundColor: "#111827", border: "1px solid #1F2937" }}>
                  <div className="text-sm font-semibold mb-4 text-[#F8FAFC]">Top Affected Assets</div>
                  <div className="flex-1 flex flex-col justify-between text-xs">
                    <AssetRow name="DB-01" count={12} width="80%" color="#EF4444" />
                    <AssetRow name="WEB-01" count={8} width="60%" color="#F59E0B" />
                    <AssetRow name="PC-12" count={6} width="40%" color="#3B82F6" />
                    <AssetRow name="SRV-04" count={4} width="30%" color="#14B8A6" />
                    <AssetRow name="APP-01" count={3} width="20%" color="#8B5CF6" />
                  </div>
                </div>
              </div>

              {/* Bottom Row */}
              <div className="grid grid-cols-3 gap-4 flex-1">
                {/* Priority Incidents Table */}
                <div className="col-span-2 rounded-xl p-4 flex flex-col overflow-hidden" style={{ backgroundColor: "#111827", border: "1px solid #1F2937" }}>
                  <div className="text-sm font-semibold mb-4 flex justify-between items-center text-[#F8FAFC]">
                    Priority Incidents
                    <span className="text-xs text-[#3B82F6] flex items-center cursor-pointer">View All <ArrowUpRight className="w-3 h-3 ml-1" /></span>
                  </div>
                  <div className="flex-1 overflow-auto">
                    <table className="w-full text-left text-xs text-[#94A3B8]">
                      <thead>
                        <tr className="border-b uppercase" style={{ borderColor: "#334155" }}>
                          <th className="pb-2 font-medium">ID</th>
                          <th className="pb-2 font-medium">Severity</th>
                          <th className="pb-2 font-medium">Risk Score</th>
                          <th className="pb-2 font-medium">Asset</th>
                          <th className="pb-2 font-medium">Technique</th>
                          <th className="pb-2 font-medium">Status</th>
                          <th className="pb-2 font-medium">Updated</th>
                        </tr>
                      </thead>
                      <tbody>
                        <TableRow id="INC-001" severity="Critical" sevColor="#EF4444" score={94} asset="DB-01" tech="T1059.001" status="Open" time="2m ago" />
                        <TableRow id="INC-002" severity="High" sevColor="#F59E0B" score={87} asset="PC-12" tech="T1078" status="Investigating" time="12m ago" />
                        <TableRow id="INC-003" severity="High" sevColor="#F59E0B" score={81} asset="WEB-01" tech="T1566" status="Open" time="28m ago" />
                        <TableRow id="INC-004" severity="Medium" sevColor="#F59E0B" score={67} asset="SRV-04" tech="T1021" status="New" time="1h ago" />
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Recent Activity & AI */}
                <div className="col-span-1 flex flex-col gap-4">
                  {/* AI Investigator Snippet */}
                  <div className="rounded-xl p-4 flex flex-col flex-1" style={{ backgroundColor: "#111827", border: "1px solid #1F2937" }}>
                    <div className="text-sm font-semibold mb-4 flex justify-between items-center text-[#F8FAFC]">
                      <div className="flex items-center gap-2">
                        <BrainCircuit className="w-4 h-4 text-[#8B5CF6]" />
                        AI Investigator
                      </div>
                      <span className="text-xs text-[#3B82F6] flex items-center cursor-pointer">View All <ArrowUpRight className="w-3 h-3 ml-1" /></span>
                    </div>
                    
                    <div className="flex-1 flex flex-col gap-3 text-xs">
                      {/* User Message */}
                      <div className="flex justify-end">
                        <div className="px-3 py-2 rounded-xl rounded-tr-sm text-[#F8FAFC] max-w-[85%]" style={{ backgroundColor: "#1F2937" }}>
                          What happened in the last 24 hours and which incidents are most critical?
                        </div>
                      </div>
                      {/* AI Response */}
                      <div className="flex gap-2">
                        <div className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0" style={{ backgroundColor: "rgba(139, 92, 246, 0.2)" }}>
                           <Shield className="w-3 h-3 text-[#8B5CF6]" />
                        </div>
                        <div className="px-3 py-2 rounded-xl rounded-tl-sm text-[#F8FAFC] flex-1 leading-relaxed" style={{ backgroundColor: "rgba(14, 165, 233, 0.1)" }}>
                          In the last 24 hours, 34 incidents were created, with 8 marked as critical. The most critical incident is <span className="text-[#3B82F6]">INC-001</span>, involving suspicious PowerShell activity on DB-01. It is linked to MITRE technique T1059.001 and affects a high-value asset.
                        </div>
                      </div>
                    </div>
                    <div className="mt-3 relative">
                      <input type="text" placeholder="Ask a question..." className="w-full bg-[#1F2937] border border-[#334155] rounded-lg px-3 py-2 text-xs focus:outline-none" />
                      <Send className="absolute right-2 top-2 w-3.5 h-3.5 text-[#14B8A6]" />
                    </div>
                  </div>
                </div>

              </div>

            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* Helper Components for the Dashboard Mockup */

function SidebarItem({ icon: Icon, label, active }: any) {
  return (
    <div className={`flex items-center gap-3 px-3 py-2 rounded-lg cursor-pointer transition-colors ${active ? "bg-[#14B8A6]/20 text-[#14B8A6]" : "text-[#94A3B8] hover:bg-[#1F2937] hover:text-[#F8FAFC]"}`}>
      <Icon className="w-4 h-4" />
      <span className="text-sm font-medium">{label}</span>
    </div>
  );
}

function KPICard({ title, value, trend, color }: any) {
  return (
    <div className="rounded-xl p-4 flex flex-col justify-between" style={{ backgroundColor: "#111827", border: "1px solid #1F2937", borderTop: `2px solid ${color}` }}>
      <div className="text-xs font-semibold text-[#94A3B8]">{title}</div>
      <div className="flex items-end justify-between mt-2">
        <div className="text-2xl font-bold text-[#F8FAFC]">{value}</div>
        <div className="text-xs font-medium" style={{ color }}>{trend}</div>
      </div>
    </div>
  );
}

function AssetRow({ name, count, width, color }: any) {
  return (
    <div className="flex items-center justify-between gap-4">
      <div className="w-12 text-[#F8FAFC]">{name}</div>
      <div className="flex-1 h-1.5 rounded-full" style={{ backgroundColor: "#1F2937" }}>
        <div className="h-full rounded-full" style={{ width, backgroundColor: color }} />
      </div>
      <div className="w-6 text-right text-[#94A3B8]">{count}</div>
    </div>
  );
}

function TableRow({ id, severity, sevColor, score, asset, tech, status, time }: any) {
  return (
    <tr className="border-b last:border-0" style={{ borderColor: "#1F2937" }}>
      <td className="py-2.5 text-[#3B82F6] font-medium">{id}</td>
      <td className="py-2.5">
        <span className="px-2 py-0.5 rounded text-[10px] font-bold" style={{ backgroundColor: `${sevColor}20`, color: sevColor }}>
          {severity}
        </span>
      </td>
      <td className="py-2.5 text-[#F8FAFC]">{score}</td>
      <td className="py-2.5 text-[#F8FAFC]">{asset}</td>
      <td className="py-2.5">{tech}</td>
      <td className="py-2.5">{status}</td>
      <td className="py-2.5">{time}</td>
    </tr>
  );
}
