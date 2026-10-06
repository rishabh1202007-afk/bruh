import { ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/Button";

export function CTA() {
  return (
    <section className="relative py-24 overflow-hidden border-b border-border-subtle">
      {/* Background with Emerald gradient */}
      <div className="absolute inset-0 bg-bg-main" />
      <div className="absolute inset-0 bg-gradient-to-br from-soft-green via-transparent to-soft-blue opacity-80" />
      <div className="absolute top-0 right-0 -translate-y-1/2 translate-x-1/2 w-[800px] h-[800px] bg-primary/10 rounded-full blur-3xl opacity-60 pointer-events-none" />

      <div className="relative max-w-4xl mx-auto px-6 lg:px-8 text-center z-10">
        <h2 className="text-4xl md:text-5xl font-bold text-text-primary tracking-tight mb-6 leading-tight">
          Ready to Upgrade Your SOC?
        </h2>
        <p className="text-xl text-text-secondary mb-10 max-w-2xl mx-auto">
          See how SentinelMesh cuts investigation time by 80% and helps analysts make confident, evidence-backed decisions.
        </p>
        
        <div className="flex flex-col sm:flex-row justify-center gap-4">
          <Button size="lg" className="w-full sm:w-auto bg-primary hover:bg-primary/90 text-white shadow-lg shadow-primary/20 text-base h-14 px-8">
            Request a Demo <ArrowRight className="ml-2 h-5 w-5" />
          </Button>
          <Button size="lg" variant="outline" className="w-full sm:w-auto bg-bg-white border-border-subtle text-text-primary hover:bg-gray-50 text-base h-14 px-8">
            View Documentation
          </Button>
        </div>
      </div>
    </section>
  );
}
