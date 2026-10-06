import { Shield } from "lucide-react";

export function Footer() {
  return (
    <footer className="bg-bg-white border-t border-border-subtle pt-16 pb-8">
      <div className="max-w-7xl mx-auto px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-12 lg:gap-8 mb-16">
          
          {/* Brand Column */}
          <div className="lg:col-span-2">
            <div className="flex items-center gap-2 mb-6">
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-soft-green text-primary">
                <Shield className="h-5 w-5" />
              </div>
              <span className="text-xl font-bold tracking-tight text-text-primary">
                SentinelMesh
              </span>
            </div>
            <p className="text-sm text-text-secondary mb-6 max-w-sm leading-relaxed">
              Designed for modern Security Operations. <br />
              Transform alerts into intelligence and investigate incidents with evidence-backed clarity.
            </p>
          </div>

          {/* Links Columns */}
          <div>
            <h4 className="font-bold text-text-primary mb-4 text-sm">Product</h4>
            <ul className="space-y-3 text-sm text-text-secondary">
              <li><a href="#" className="hover:text-primary transition-colors">Features</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Architecture</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">AI Investigator</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Integrations</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Pricing</a></li>
            </ul>
          </div>

          <div>
            <h4 className="font-bold text-text-primary mb-4 text-sm">Resources</h4>
            <ul className="space-y-3 text-sm text-text-secondary">
              <li><a href="#" className="hover:text-primary transition-colors">Documentation</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Blog</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Threat Intel</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">API Reference</a></li>
            </ul>
          </div>

          <div>
            <h4 className="font-bold text-text-primary mb-4 text-sm">Company</h4>
            <ul className="space-y-3 text-sm text-text-secondary">
              <li><a href="#" className="hover:text-primary transition-colors">About Us</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Contact</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Careers</a></li>
              <li><a href="#" className="hover:text-primary transition-colors">Trust Center</a></li>
            </ul>
          </div>

        </div>

        <div className="flex flex-col md:flex-row items-center justify-between pt-8 border-t border-border-subtle text-xs text-text-secondary gap-4">
          <div>
            &copy; {new Date().getFullYear()} SentinelMesh, Inc. All rights reserved.
          </div>
          <div className="flex gap-6">
            <a href="#" className="hover:text-primary transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-primary transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-primary transition-colors">Cookie Settings</a>
          </div>
        </div>
      </div>
    </footer>
  );
}
