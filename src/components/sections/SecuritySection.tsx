import { ShieldCheck, Lock, FileKey, CheckCircle } from "lucide-react";

const compliances = [
  "SOC 2 Type II Certified",
  "ISO 27001 Certified",
  "GDPR Compliant",
  "HIPAA Compliant"
];

export function SecuritySection() {
  return (
    <section className="py-24 bg-bg-white border-b border-border-subtle relative overflow-hidden">
      {/* Subtle background element */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-soft-green rounded-full blur-3xl opacity-30 pointer-events-none" />

      <div className="max-w-7xl mx-auto px-6 lg:px-8 relative z-10">
        <div className="text-center max-w-3xl mx-auto mb-16">
          <h2 className="text-3xl md:text-4xl font-bold text-text-primary tracking-tight mb-4">
            Built for <span className="text-gradient">Security First</span>
          </h2>
          <p className="text-lg text-text-secondary">
            Your telemetry data is highly sensitive. We protect it with military-grade encryption, strict access controls, and comprehensive compliance standards.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8 mb-16">
          
          <div className="flex flex-col items-center text-center">
            <div className="w-12 h-12 rounded-xl bg-soft-green flex items-center justify-center text-primary mb-4 border border-primary/10">
              <Lock className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-text-primary mb-2">End-to-End Encryption</h3>
            <p className="text-sm text-text-secondary">AES-256 encryption at rest and TLS 1.3 in transit. Bring your own key (BYOK) supported.</p>
          </div>

          <div className="flex flex-col items-center text-center">
            <div className="w-12 h-12 rounded-xl bg-soft-blue flex items-center justify-center text-accent mb-4 border border-accent/10">
              <FileKey className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-text-primary mb-2">Zero Trust Architecture</h3>
            <p className="text-sm text-text-secondary">Strict RBAC, mandatory MFA, and continuous authentication across all platform services.</p>
          </div>

          <div className="flex flex-col items-center text-center">
            <div className="w-12 h-12 rounded-xl bg-soft-purple flex items-center justify-center text-accent-ai mb-4 border border-accent-ai/10">
              <ShieldCheck className="w-6 h-6" />
            </div>
            <h3 className="text-lg font-bold text-text-primary mb-2">Data Privacy & Sovereignty</h3>
            <p className="text-sm text-text-secondary">Choose your deployment region. We never use your security data to train public AI models.</p>
          </div>

        </div>

        {/* Clean text-based compliance markers */}
        <div className="flex flex-wrap justify-center gap-4 md:gap-8 border-t border-border-subtle pt-12">
          {compliances.map((compliance) => (
            <div key={compliance} className="flex items-center gap-2 text-text-primary font-semibold text-sm">
              <CheckCircle className="w-4 h-4 text-primary" />
              {compliance}
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}
