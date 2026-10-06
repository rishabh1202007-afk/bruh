import { Network, Server, User, Monitor, Key, Terminal, ArrowRight } from "lucide-react";

export function AttackGraph() {
  return (
    <section className="py-24 bg-bg-white border-b border-border-subtle overflow-hidden">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-4">
            Interactive <span className="text-gradient">Attack Graph</span>
          </h2>
          <p className="text-lg text-text-secondary">
            Visually trace the lateral movement of an attack across your infrastructure.
          </p>
        </div>

        <div className="relative w-full max-w-5xl mx-auto h-[400px] bg-bg-main border border-border-subtle rounded-2xl shadow-sm flex items-center justify-center p-8 overflow-x-auto">
          {/* Subtle background grid */}
          <div className="absolute inset-0 opacity-20" style={{ backgroundImage: 'radial-gradient(circle at 1px 1px, var(--border-subtle) 1px, transparent 0)', backgroundSize: '32px 32px' }} />

          <div className="flex items-center min-w-max relative z-10 gap-4 md:gap-8">
            
            {/* Source IP */}
            <div className="flex flex-col items-center">
              <div className="w-16 h-16 rounded-2xl bg-white border border-border-subtle shadow flex items-center justify-center text-primary mb-3">
                <Network className="w-7 h-7" />
              </div>
              <div className="text-xs font-bold text-text-primary">203.0.113.42</div>
              <div className="text-[10px] text-text-secondary">Source IP</div>
            </div>

            <ArrowRight className="w-6 h-6 text-border-subtle shrink-0" />

            {/* User */}
            <div className="flex flex-col items-center">
              <div className="w-16 h-16 rounded-2xl bg-white border border-border-subtle shadow flex items-center justify-center text-primary mb-3">
                <User className="w-7 h-7" />
              </div>
              <div className="text-xs font-bold text-text-primary">j.doe</div>
              <div className="text-[10px] text-text-secondary">Compromised User</div>
            </div>

            <ArrowRight className="w-6 h-6 text-border-subtle shrink-0" />

            {/* Workstation */}
            <div className="flex flex-col items-center">
              <div className="w-16 h-16 rounded-2xl bg-white border-2 border-accent shadow flex items-center justify-center text-accent mb-3">
                <Monitor className="w-7 h-7" />
              </div>
              <div className="text-xs font-bold text-text-primary">LPT-842</div>
              <div className="text-[10px] text-text-secondary">Workstation</div>
            </div>

            <ArrowRight className="w-6 h-6 text-red-300 shrink-0" />

            {/* Suspicious Process */}
            <div className="flex flex-col items-center transform -translate-y-4">
              <div className="w-16 h-16 rounded-2xl bg-red-50 border-2 border-red-500 shadow-md flex items-center justify-center text-red-600 mb-3 animate-pulse">
                <Terminal className="w-7 h-7" />
              </div>
              <div className="text-xs font-bold text-red-600">powershell.exe</div>
              <div className="text-[10px] text-red-500/80">Suspicious Process</div>
            </div>

            <ArrowRight className="w-6 h-6 text-red-300 shrink-0" />

            {/* Credential Activity */}
            <div className="flex flex-col items-center">
              <div className="w-16 h-16 rounded-2xl bg-soft-purple border border-accent-ai shadow flex items-center justify-center text-accent-ai mb-3">
                <Key className="w-7 h-7" />
              </div>
              <div className="text-xs font-bold text-accent-ai">LSASS Access</div>
              <div className="text-[10px] text-accent-ai/80">Credential Dumping</div>
            </div>

            <ArrowRight className="w-6 h-6 text-border-subtle shrink-0" />

            {/* Server */}
            <div className="flex flex-col items-center">
              <div className="w-16 h-16 rounded-2xl bg-white border-2 border-accent shadow flex items-center justify-center text-accent mb-3">
                <Server className="w-7 h-7" />
              </div>
              <div className="text-xs font-bold text-text-primary">DB-PROD-01</div>
              <div className="text-[10px] text-text-secondary">Target Server</div>
            </div>

          </div>
        </div>
      </div>
    </section>
  );
}
