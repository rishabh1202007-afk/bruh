import { Zap, Target, Search, Network } from "lucide-react";

const metrics = [
  {
    number: "01",
    title: "Alert Correlation",
    description: "Turn noisy security events into meaningful incidents.",
    icon: Zap,
  },
  {
    number: "02",
    title: "Risk Prioritization",
    description: "Combine severity, confidence and asset criticality.",
    icon: Target,
  },
  {
    number: "03",
    title: "Evidence Traceability",
    description: "Keep investigation conclusions connected to evidence.",
    icon: Search,
  },
  {
    number: "04",
    title: "Threat Mapping",
    description: "Map observed behaviors to MITRE ATT&CK techniques.",
    icon: Network,
  },
];

export function Metrics() {
  return (
    <section className="bg-bg-white py-16 border-b border-border-subtle relative z-20">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 lg:gap-12 divide-y md:divide-y-0 md:divide-x divide-border-subtle">
          {metrics.map((metric, i) => (
            <div key={metric.title} className={`pt-6 md:pt-0 ${i !== 0 ? "md:pl-8 lg:pl-12" : ""}`}>
              <div className="flex items-center gap-4 mb-4">
                <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-soft-green flex items-center justify-center text-primary">
                  <metric.icon className="w-5 h-5" />
                </div>
                <div className="text-xl font-bold text-border-subtle font-mono">
                  {metric.number}
                </div>
              </div>
              <h3 className="text-lg font-semibold text-text-primary mb-2">
                {metric.title}
              </h3>
              <p className="text-sm text-text-secondary leading-relaxed">
                {metric.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
