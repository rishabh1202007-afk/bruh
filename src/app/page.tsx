import { Navbar } from "@/components/sections/Navbar";
import { Hero } from "@/components/sections/Hero";
import { Metrics } from "@/components/sections/Metrics";
import { ProblemSolution } from "@/components/sections/ProblemSolution";
import { Features } from "@/components/sections/Features";
import { Workflow } from "@/components/sections/Workflow";
import { DashboardPreview } from "@/components/sections/DashboardPreview";
import { AIInvestigator } from "@/components/sections/AIInvestigator";
import { MitreSection } from "@/components/sections/MitreSection";
import { AttackGraph } from "@/components/sections/AttackGraph";
import { Architecture } from "@/components/sections/Architecture";
import { SecuritySection } from "@/components/sections/SecuritySection";
import { CTA } from "@/components/sections/CTA";
import { Footer } from "@/components/sections/Footer";

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col relative overflow-x-hidden">
      <Navbar />
      <Hero />
      <Metrics />
      <ProblemSolution />
      <Features />
      <Workflow />
      <DashboardPreview />
      <AIInvestigator />
      <MitreSection />
      <AttackGraph />
      <Architecture />
      <SecuritySection />
      <CTA />
      <Footer />
    </main>
  );
}
