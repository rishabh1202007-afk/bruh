import { ArrowRight, ShieldCheck, Activity, Search, BrainCircuit, Network } from "lucide-react";
import { Button } from "@/components/ui/Button";

export function Hero() {
  return (
    <section className="relative pt-32 pb-24 overflow-hidden bg-bg-main">
      {/* Background patterns and subtle gradients */}
      <div className="absolute inset-0 bg-gradient-to-br from-soft-green/50 via-bg-main to-soft-blue/50" />
      <div className="absolute top-0 right-0 -translate-y-12 translate-x-1/3 w-[800px] h-[800px] bg-primary/5 rounded-full blur-3xl opacity-50 pointer-events-none" />
      <div className="absolute bottom-0 left-0 translate-y-1/3 -translate-x-1/3 w-[600px] h-[600px] bg-secondary/5 rounded-full blur-3xl opacity-50 pointer-events-none" />

      <div className="relative max-w-7xl mx-auto px-6 lg:px-8 grid lg:grid-cols-2 gap-16 items-center z-10">
        
        {/* Left Column: Copy & CTAs */}
        <div className="flex flex-col items-start text-left">
          <div className="inline-flex items-center rounded-full border border-primary/20 bg-soft-green px-3 py-1 text-[13px] font-semibold tracking-wide text-primary mb-6">
            <ShieldCheck className="mr-1.5 h-4 w-4" />
            SECURITY INCIDENT INTELLIGENCE PLATFORM
          </div>
          
          <h1 className="text-5xl lg:text-6xl xl:text-7xl font-bold text-text-primary tracking-tight mb-6 leading-[1.1]">
            Smarter Detection. <br />
            <span className="text-gradient">Faster Investigation.</span>
          </h1>
          
          <p className="text-lg lg:text-xl text-text-secondary mb-10 max-w-xl leading-relaxed">
            SentinelMesh transforms security alerts into correlated, prioritized, evidence-backed incidents—helping analysts understand what happened, why it matters, and what to investigate next.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 w-full sm:w-auto mb-8">
            <Button size="lg" className="w-full sm:w-auto bg-primary hover:bg-primary/90 text-white shadow-md shadow-primary/20">
              Get Started <ArrowRight className="ml-2 h-5 w-5" />
            </Button>
            <Button size="lg" variant="outline" className="w-full sm:w-auto bg-bg-white border-border-subtle text-text-primary hover:bg-gray-50 shadow-sm">
              Explore Architecture
            </Button>
          </div>

          <div className="text-sm font-medium text-text-secondary flex items-center gap-2">
            <span>Deterministic security intelligence</span>
            <span className="w-1 h-1 rounded-full bg-border-subtle" />
            <span>Evidence-backed investigation</span>
            <span className="w-1 h-1 rounded-full bg-border-subtle" />
            <span>Grounded AI</span>
          </div>
        </div>

        {/* Right Column: Isometric Dashboard Visualization */}
        <div className="relative w-full h-[500px] lg:h-[600px] hidden md:block">
          
          {/* Main Dashboard Mockup */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] bg-bg-white rounded-2xl border border-border-subtle shadow-2xl overflow-hidden flex flex-col transform perspective-1000 rotate-y-[-5deg] rotate-x-[5deg]">
            {/* Header */}
            <div className="h-12 border-b border-border-subtle flex items-center px-4 bg-gray-50">
              <div className="flex gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-red-400" />
                <div className="w-2.5 h-2.5 rounded-full bg-yellow-400" />
                <div className="w-2.5 h-2.5 rounded-full bg-green-400" />
              </div>
              <div className="ml-4 w-48 h-5 bg-white border border-border-subtle rounded-md shadow-sm" />
            </div>
            {/* Body */}
            <div className="flex-1 flex bg-gray-50/50 p-4 gap-4">
              {/* Sidebar */}
              <div className="w-32 flex flex-col gap-2">
                <div className="h-6 w-full bg-primary/10 rounded-md" />
                <div className="h-6 w-3/4 bg-border-subtle/50 rounded-md" />
                <div className="h-6 w-5/6 bg-border-subtle/50 rounded-md" />
                <div className="h-6 w-2/3 bg-border-subtle/50 rounded-md" />
              </div>
              {/* Main Content */}
              <div className="flex-1 flex flex-col gap-4">
                {/* Stats Row */}
                <div className="flex gap-4">
                  <div className="flex-1 h-20 bg-white border border-border-subtle rounded-xl shadow-sm p-3 flex flex-col justify-between">
                    <div className="w-6 h-6 rounded bg-red-100" />
                    <div className="w-12 h-4 bg-gray-200 rounded" />
                  </div>
                  <div className="flex-1 h-20 bg-white border border-border-subtle rounded-xl shadow-sm p-3 flex flex-col justify-between">
                    <div className="w-6 h-6 rounded bg-yellow-100" />
                    <div className="w-12 h-4 bg-gray-200 rounded" />
                  </div>
                  <div className="flex-1 h-20 bg-white border border-border-subtle rounded-xl shadow-sm p-3 flex flex-col justify-between">
                    <div className="w-6 h-6 rounded bg-green-100" />
                    <div className="w-12 h-4 bg-gray-200 rounded" />
                  </div>
                </div>
                {/* Graph Area */}
                <div className="flex-1 bg-white border border-border-subtle rounded-xl shadow-sm relative overflow-hidden">
                  <div className="absolute bottom-0 left-0 w-full h-1/2 bg-gradient-to-t from-primary/10 to-transparent" />
                  <svg className="absolute inset-0 w-full h-full" preserveAspectRatio="none" viewBox="0 0 100 100">
                    <path d="M0,80 Q25,50 50,70 T100,20 L100,100 L0,100 Z" fill="rgba(16, 185, 129, 0.1)" />
                    <path d="M0,80 Q25,50 50,70 T100,20" fill="none" stroke="#10B981" strokeWidth="2" />
                  </svg>
                </div>
              </div>
            </div>
          </div>

          {/* Floating Info Cards */}
          <div className="absolute top-10 left-0 bg-white p-3 rounded-xl shadow-lg border border-border-subtle flex items-center gap-3 animate-float-slow">
            <div className="w-8 h-8 rounded-full bg-soft-green flex items-center justify-center text-primary">
              <Activity className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-text-primary">Real-time</div>
              <div className="text-[10px] text-text-secondary">Threat Detection</div>
            </div>
          </div>

          <div className="absolute top-32 -right-4 bg-white p-3 rounded-xl shadow-lg border border-border-subtle flex items-center gap-3 animate-float-delayed">
            <div className="w-8 h-8 rounded-full bg-soft-blue flex items-center justify-center text-accent">
              <Network className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-text-primary">Attack Graph</div>
              <div className="text-[10px] text-text-secondary">Visualization</div>
            </div>
          </div>

          <div className="absolute bottom-20 -left-6 bg-white p-3 rounded-xl shadow-lg border border-border-subtle flex items-center gap-3 animate-float">
            <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center text-gray-600">
              <Search className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-text-primary">Evidence-backed</div>
              <div className="text-[10px] text-text-secondary">Investigation</div>
            </div>
          </div>

          <div className="absolute bottom-4 right-10 bg-white p-3 rounded-xl shadow-lg border border-border-subtle flex items-center gap-3 animate-float-slow">
            <div className="w-8 h-8 rounded-full bg-soft-purple flex items-center justify-center text-accent-ai">
              <BrainCircuit className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-text-primary">AI Investigation</div>
              <div className="text-[10px] text-text-secondary">Assistant</div>
            </div>
          </div>

        </div>
      </div>
    </section>
  );
}
