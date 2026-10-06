import { ArrowRight, Crosshair } from "lucide-react";

const mitreStages = [
  {
    tactic: "Initial Access",
    techniques: ["T1190 - Exploit Public-Facing Application", "T1078 - Valid Accounts"],
  },
  {
    tactic: "Execution",
    techniques: ["T1059 - Command and Scripting Interpreter"],
  },
  {
    tactic: "Credential Access",
    techniques: ["T1003 - OS Credential Dumping", "T1555 - Credentials from Password Stores"],
  },
  {
    tactic: "Lateral Movement",
    techniques: ["T1021 - Remote Services"],
  },
  {
    tactic: "Impact",
    techniques: ["T1486 - Data Encrypted for Impact"],
  },
];

export function MitreSection() {
  return (
    <section className="py-24 bg-bg-main overflow-hidden border-b border-border-subtle">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <div className="inline-flex items-center rounded-full border border-primary/20 bg-soft-green px-3 py-1 text-sm font-semibold text-primary mb-6">
            <Crosshair className="mr-2 h-4 w-4" />
            ATT&CK Framework Integration
          </div>
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-4">
            Understand the <span className="text-gradient">Attack Path</span>
          </h2>
          <p className="text-lg text-text-secondary">
            SentinelMesh dynamically maps observed behaviors to the MITRE ATT&CK matrix. We present this mapping as evidence-supported behavioral indicators, not assumptions.
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          <div className="flex flex-col gap-6 relative">
            {/* Connecting line */}
            <div className="absolute left-[1.125rem] md:left-[1.375rem] top-6 bottom-6 w-0.5 bg-border-subtle" />

            {mitreStages.map((stage, index) => (
              <div key={stage.tactic} className="relative flex items-start gap-6 group">
                {/* Node */}
                <div className="w-10 h-10 md:w-12 md:h-12 rounded-full bg-bg-white border-2 border-border-subtle flex items-center justify-center shrink-0 z-10 transition-colors group-hover:border-primary">
                  <div className="w-2.5 h-2.5 md:w-3 md:h-3 rounded-full bg-border-subtle group-hover:bg-primary transition-colors" />
                </div>

                {/* Content Card */}
                <div className="flex-1 bg-bg-white border border-border-subtle rounded-2xl p-5 shadow-sm hover:shadow-md transition-shadow group-hover:border-primary/30">
                  <h3 className="text-lg font-bold text-text-primary mb-4">
                    {stage.tactic}
                  </h3>
                  <div className="flex flex-wrap gap-2">
                    {stage.techniques.map((tech) => (
                      <span key={tech} className="inline-flex items-center text-xs font-medium bg-soft-blue text-accent border border-accent/20 px-2.5 py-1.5 rounded-lg">
                        {tech}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
