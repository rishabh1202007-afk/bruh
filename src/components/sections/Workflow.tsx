import { ArrowRight, ArrowDown } from "lucide-react";

const pipelineStages = [
  {
    category: "Data Ingestion & Processing",
    steps: ["Security Sources", "Ingestion", "Validation", "Normalization"],
  },
  {
    category: "Detection Engine",
    steps: ["Detection", "Deduplication", "Enrichment", "Correlation"],
  },
  {
    category: "Intelligence Layer",
    steps: ["Incident Creation", "Risk & Priority", "MITRE ATT&CK", "Timeline / Attack Graph", "Evidence"],
  },
  {
    category: "Security Operations",
    steps: ["AI Investigation", "Analyst Action"],
  }
];

export function Workflow() {
  return (
    <section id="workflow" className="py-24 bg-bg-white border-b border-border-subtle">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-4">
            A Purpose-Built <span className="text-gradient">Security Data Pipeline</span>
          </h2>
          <p className="text-lg text-text-secondary">
            Every stage of the SentinelMesh pipeline is optimized for converting raw, noisy security events into highly actionable intelligence.
          </p>
        </div>

        <div className="relative max-w-5xl mx-auto">
          <div className="flex flex-col gap-8 lg:gap-12 relative z-10">
            {pipelineStages.map((stage, stageIndex) => (
              <div key={stage.category} className="flex flex-col lg:flex-row gap-6 lg:gap-12 lg:items-center">
                {/* Category Label */}
                <div className="lg:w-48 flex-shrink-0">
                  <h3 className="text-sm font-bold text-text-secondary uppercase tracking-wider">
                    {stage.category}
                  </h3>
                </div>

                {/* Nodes */}
                <div className="flex-1 bg-bg-main border border-border-subtle rounded-2xl p-6 shadow-sm flex flex-wrap items-center gap-3 relative">
                  {stage.steps.map((step, stepIndex) => (
                    <div key={step} className="flex items-center gap-3">
                      <div className={`px-4 py-2 rounded-lg border text-sm font-medium shadow-sm whitespace-nowrap transition-colors ${
                        stageIndex === pipelineStages.length - 1 && stepIndex === stage.steps.length - 1
                          ? "bg-primary text-white border-primary shadow-primary/20"
                          : "bg-bg-white border-border-subtle text-text-primary hover:border-primary/40"
                      }`}>
                        {step}
                      </div>
                      {stepIndex < stage.steps.length - 1 && (
                        <ArrowRight className="w-4 h-4 text-border-subtle hidden sm:block" />
                      )}
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Visual vertical connection line on desktop */}
          <div className="hidden lg:block absolute top-10 bottom-10 left-[11rem] w-px bg-border-subtle z-0" />
        </div>
      </div>
    </section>
  );
}
