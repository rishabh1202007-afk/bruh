import { ArrowDown } from "lucide-react";

const traditionalSteps = [
  "Thousands of Alerts",
  "Duplicate Events",
  "Noise",
  "Manual Investigation",
  "Delayed Response",
];

const sentinelSteps = [
  "Events",
  "Normalization",
  "Detection",
  "Noise Reduction",
  "Correlation",
  "Incident Creation",
  "Risk Scoring",
  "Evidence-backed Investigation",
];

export function ProblemSolution() {
  return (
    <section className="py-24 bg-bg-main overflow-hidden border-b border-border-subtle">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-20">
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-6">
            From Alert Overload to <br className="hidden sm:block" />
            <span className="text-gradient">Actionable Intelligence</span>
          </h2>
          <p className="text-lg text-text-secondary">
            Traditional SIEMs leave analysts drowning in noise. SentinelMesh automates the heavy lifting of correlation and prioritization.
          </p>
        </div>

        <div className="grid md:grid-cols-2 gap-12 lg:gap-24 relative">
          
          {/* Subtle connecting background line between columns on desktop */}
          <div className="hidden md:block absolute left-1/2 top-10 bottom-10 w-px bg-gradient-to-b from-transparent via-border-subtle to-transparent -translate-x-1/2" />

          {/* Left: Traditional Workflow */}
          <div className="relative">
            <h3 className="text-xl font-semibold text-text-primary mb-10 text-center">
              Traditional Security Workflow
            </h3>
            <div className="flex flex-col items-center">
              {traditionalSteps.map((step, index) => (
                <div key={step} className="flex flex-col items-center w-full">
                  <div className="w-full max-w-xs bg-bg-white border border-border-subtle rounded-xl p-4 text-center shadow-sm text-text-secondary opacity-70">
                    <span className="font-medium">{step}</span>
                  </div>
                  {index < traditionalSteps.length - 1 && (
                    <div className="py-3 text-border-subtle">
                      <ArrowDown className="w-5 h-5" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* Right: SentinelMesh Workflow */}
          <div className="relative">
            <h3 className="text-xl font-semibold text-primary mb-10 text-center">
              SentinelMesh
            </h3>
            <div className="flex flex-col items-center">
              {sentinelSteps.map((step, index) => (
                <div key={step} className="flex flex-col items-center w-full group">
                  <div className={`w-full max-w-xs bg-bg-white border rounded-xl p-4 text-center shadow-sm transition-all duration-300 ${
                    index === sentinelSteps.length - 1 
                      ? "border-primary/50 shadow-primary/10 bg-soft-green/50 text-primary font-semibold" 
                      : "border-primary/20 text-text-primary hover:border-primary hover:shadow-md"
                  }`}>
                    <span className="font-medium">{step}</span>
                  </div>
                  {index < sentinelSteps.length - 1 && (
                    <div className="py-2.5 text-primary/40 relative">
                      {/* Subtle connecting line with dot */}
                      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-1 h-1 rounded-full bg-primary/50" />
                      <ArrowDown className="w-5 h-5" />
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
