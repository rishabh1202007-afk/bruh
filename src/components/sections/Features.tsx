import { ArrowRight, Zap, Combine, ShieldAlert, Clock, Crosshair, BrainCircuit } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from "@/components/ui/Card";

const features = [
  {
    label: "Detection",
    title: "Alert Intelligence",
    description: "Normalize security events, detect meaningful activity and reduce duplicate/noisy alerts.",
    icon: Zap,
  },
  {
    label: "Intelligence",
    title: "Incident Correlation",
    description: "Correlate events across users, IPs, hosts, sessions, processes and time.",
    icon: Combine,
  },
  {
    label: "Prioritization",
    title: "Explainable Risk",
    description: "Generate deterministic risk scores using severity, confidence, asset criticality and contextual factors.",
    icon: ShieldAlert,
  },
  {
    label: "Investigation",
    title: "Attack Timeline",
    description: "Reconstruct the sequence of events so analysts can understand how an incident unfolded.",
    icon: Clock,
  },
  {
    label: "Mapping",
    title: "MITRE ATT&CK Mapping",
    description: "Map observed behavior to relevant MITRE ATT&CK techniques while keeping the mapping evidence-supported.",
    icon: Crosshair,
  },
  {
    label: "AI",
    title: "Grounded AI Investigator",
    description: "Use retrieval-augmented investigation assistance with evidence references and explicit uncertainty.",
    icon: BrainCircuit,
  },
];

export function Features() {
  return (
    <section id="features" className="py-24 bg-bg-main border-b border-border-subtle">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary mb-4 tracking-tight">
            Everything an Analyst Needs to <br className="hidden md:block"/> <span className="text-gradient">Investigate an Incident</span>
          </h2>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6 lg:gap-8">
          {features.map((feature, index) => (
            <Card key={index} className="group overflow-hidden relative border-border-subtle bg-bg-white hover:border-primary/40 hover:shadow-lg hover:shadow-primary/5 transition-all duration-300 flex flex-col rounded-[20px]">
              {/* Subtle hover background gradient */}
              <div className="absolute inset-0 bg-gradient-to-b from-soft-green/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
              
              <CardHeader className="relative flex-1 p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="bg-bg-main border border-border-subtle p-3 rounded-xl group-hover:border-primary/30 group-hover:bg-primary/5 transition-colors duration-300 shadow-sm">
                    <feature.icon className="w-5 h-5 text-text-primary group-hover:text-primary transition-colors duration-300" />
                  </div>
                  <span className="text-[11px] font-bold tracking-widest text-text-secondary uppercase">
                    {feature.label}
                  </span>
                </div>
                <CardTitle className="text-xl mb-3 text-text-primary font-semibold tracking-tight">{feature.title}</CardTitle>
                <CardDescription className="text-[15px] text-text-secondary leading-relaxed">
                  {feature.description}
                </CardDescription>
              </CardHeader>
              <CardFooter className="relative mt-auto pt-0 pb-6 px-6">
                <button className="flex items-center text-sm font-semibold text-text-primary group-hover:text-primary transition-colors duration-300">
                  Explore feature 
                  <ArrowRight className="w-4 h-4 ml-1.5 opacity-0 -translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-300" />
                </button>
              </CardFooter>
            </Card>
          ))}
        </div>
      </div>
    </section>
  );
}
