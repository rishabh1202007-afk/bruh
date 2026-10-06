import { Database, Activity, GitMerge, DatabaseZap } from "lucide-react";

const architecture = [
  {
    title: "Data Ingestion",
    description: "Handle 100k+ EPS with schemaless parsing and dynamic normalization pipelines.",
    icon: DatabaseZap,
    metrics: ["100k+ EPS", "Schemaless", "Dynamic Normalization"]
  },
  {
    title: "Correlation Engine",
    description: "Graph-based memory structures maintain real-time state across millions of events.",
    icon: GitMerge,
    metrics: ["Graph-based", "Stateful", "Real-time"]
  },
  {
    title: "Analytics & Detection",
    description: "Combine deterministic rules with behavioral machine learning models.",
    icon: Activity,
    metrics: ["ML Models", "YARA-L Support", "Deterministic"]
  },
  {
    title: "Storage & Search",
    description: "Hot/Cold tiering with sub-second search capabilities across petabytes of data.",
    icon: Database,
    metrics: ["Hot/Cold Tiering", "Petabyte Scale", "Sub-second Query"]
  }
];

export function Architecture() {
  return (
    <section id="architecture" className="py-24 bg-bg-main border-b border-border-subtle">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="flex flex-col md:flex-row md:items-end justify-between mb-16 gap-6">
          <div className="max-w-2xl">
            <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-4">
              Enterprise-Grade <span className="text-gradient">Scalability</span>
            </h2>
            <p className="text-lg text-text-secondary">
              Built from the ground up to handle the volume, velocity, and variety of modern security telemetry without compromising search speed or correlation depth.
            </p>
          </div>
        </div>

        <div className="grid md:grid-cols-2 gap-6 lg:gap-8">
          {architecture.map((item) => (
            <div key={item.title} className="bg-bg-white border border-border-subtle rounded-2xl p-6 lg:p-8 flex flex-col hover:border-primary/30 transition-colors shadow-sm">
              <div className="w-12 h-12 rounded-xl bg-soft-blue flex items-center justify-center text-accent mb-6 border border-accent/10">
                <item.icon className="w-6 h-6" />
              </div>
              
              <h3 className="text-xl font-bold text-text-primary mb-3">{item.title}</h3>
              <p className="text-text-secondary mb-6 leading-relaxed">{item.description}</p>
              
              <div className="mt-auto flex flex-wrap gap-2">
                {item.metrics.map((metric) => (
                  <span key={metric} className="inline-flex items-center text-xs font-medium bg-gray-50 text-text-secondary border border-border-subtle px-2.5 py-1 rounded">
                    {metric}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
