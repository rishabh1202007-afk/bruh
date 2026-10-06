import { BrainCircuit, CheckCircle2, Shield, Search, FileText } from "lucide-react";

export function AIInvestigator() {
  return (
    <section className="py-24 bg-bg-white border-b border-border-subtle overflow-hidden">
      <div className="max-w-7xl mx-auto px-6 lg:px-8 grid lg:grid-cols-2 gap-16 items-center">
        
        {/* Left Column: Description */}
        <div>
          <div className="inline-flex items-center rounded-full border border-accent-ai/20 bg-soft-purple px-3 py-1 text-sm font-semibold text-accent-ai mb-6">
            <BrainCircuit className="mr-2 h-4 w-4" />
            AI Investigation Assistant
          </div>
          
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-6">
            Investigation Assistance, <br />
            <span className="text-gradient-ai">Grounded in Evidence.</span>
          </h2>
          
          <p className="text-lg text-text-secondary mb-8 leading-relaxed">
            The AI Investigator acts as a force multiplier for your team. It accelerates analysis by parsing vast amounts of correlated data and generating natural language summaries, but it never makes authoritative decisions without showing its work.
          </p>

          <ul className="space-y-4">
            <li className="flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-primary shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-text-primary block">Evidence-backed responses</span>
                <span className="text-text-secondary text-sm">Every assertion is linked directly to raw logs, alerts, or system state.</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-primary shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-text-primary block">Retrieval-augmented context</span>
                <span className="text-text-secondary text-sm">Queries are enriched with historical incident data and threat intelligence.</span>
              </div>
            </li>
            <li className="flex items-start gap-3">
              <CheckCircle2 className="w-5 h-5 text-primary shrink-0 mt-0.5" />
              <div>
                <span className="font-semibold text-text-primary block">Explicit uncertainty</span>
                <span className="text-text-secondary text-sm">The AI highlights what is known versus what is inferred or missing.</span>
              </div>
            </li>
          </ul>
        </div>

        {/* Right Column: AI Chat Mockup */}
        <div className="relative">
          <div className="absolute inset-0 bg-gradient-to-br from-soft-purple to-transparent rounded-3xl transform rotate-3 scale-105 opacity-50" />
          <div className="relative bg-bg-white border border-border-subtle rounded-2xl shadow-xl overflow-hidden flex flex-col h-[500px]">
            {/* Header */}
            <div className="bg-bg-main border-b border-border-subtle p-4 flex items-center gap-3">
              <div className="w-8 h-8 rounded-full bg-accent-ai/10 flex items-center justify-center">
                <BrainCircuit className="w-5 h-5 text-accent-ai" />
              </div>
              <div>
                <div className="text-sm font-bold text-text-primary">SentinelMesh Assistant</div>
                <div className="text-[11px] text-text-secondary">Investigation Mode</div>
              </div>
            </div>

            {/* Chat Area */}
            <div className="flex-1 p-6 flex flex-col gap-6 overflow-y-auto bg-gray-50/50">
              {/* Analyst Query */}
              <div className="flex justify-end">
                <div className="bg-bg-white border border-border-subtle p-4 rounded-2xl rounded-tr-sm text-sm text-text-primary shadow-sm max-w-[85%]">
                  What happened in this incident?
                </div>
              </div>

              {/* AI Response */}
              <div className="flex gap-4">
                <div className="w-8 h-8 rounded-full bg-soft-purple flex items-center justify-center shrink-0">
                  <Shield className="w-4 h-4 text-accent-ai" />
                </div>
                <div className="flex flex-col gap-3">
                  <div className="bg-soft-blue border border-accent/10 p-4 rounded-2xl rounded-tl-sm text-sm text-text-primary leading-relaxed shadow-sm">
                    The incident contains correlated authentication, process and network activity involving the affected asset <code className="bg-white px-1.5 py-0.5 rounded border border-border-subtle text-xs font-mono">db-prod-01</code>.
                    <br /><br />
                    Multiple failed login attempts were followed by a successful login and immediate execution of suspicious PowerShell commands.
                  </div>

                  {/* Evidence References */}
                  <div className="bg-bg-white border border-border-subtle rounded-xl p-3 shadow-sm">
                    <div className="text-[10px] font-bold tracking-widest text-text-secondary mb-2 uppercase flex items-center gap-1.5">
                      <Search className="w-3 h-3" /> Evidence Referenced
                    </div>
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-xs p-2 rounded bg-gray-50 border border-border-subtle">
                        <FileText className="w-3.5 h-3.5 text-accent" />
                        <span className="font-medium text-text-primary">Event #EV-1023</span>
                        <span className="text-text-secondary truncate">- Authentication activity</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs p-2 rounded bg-gray-50 border border-border-subtle">
                        <FileText className="w-3.5 h-3.5 text-red-500" />
                        <span className="font-medium text-text-primary">Alert #AL-2231</span>
                        <span className="text-text-secondary truncate">- Suspicious Process activity</span>
                      </div>
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
