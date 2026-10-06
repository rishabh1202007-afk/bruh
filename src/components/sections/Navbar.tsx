"use client";

import { useEffect, useState } from "react";
import { ArrowRight, Shield } from "lucide-react";
import { Button } from "@/components/ui/Button";

const navLinks = [
  { name: "Home", href: "#", active: true },
  { name: "Features", href: "#features", active: false },
  { name: "Architecture", href: "#architecture", active: false },
  { name: "How It Works", href: "#workflow", active: false },
  { name: "Documentation", href: "#", active: false },
  { name: "About", href: "#", active: false },
];

export function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  return (
    <nav
      className={`fixed top-0 z-50 w-full transition-all duration-300 ${
        isScrolled
          ? "bg-bg-white/90 backdrop-blur-md shadow-sm border-b border-border-subtle"
          : "bg-bg-white border-b border-transparent"
      }`}
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6 lg:px-8">
        <div className="flex items-center gap-2">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-soft-green text-primary">
            <Shield className="h-5 w-5" />
          </div>
          <span className="text-xl font-bold tracking-tight text-text-primary">
            SentinelMesh
          </span>
        </div>

        <div className="hidden md:flex items-center gap-8">
          {navLinks.map((link) => (
            <a
              key={link.name}
              href={link.href}
              className={`relative text-[13px] font-semibold tracking-wide transition-colors ${
                link.active
                  ? "text-primary"
                  : "text-text-secondary hover:text-text-primary"
              }`}
            >
              {link.name}
              {link.active && (
                <span className="absolute -bottom-6 left-0 right-0 h-0.5 bg-primary rounded-t-md" />
              )}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-4">
          <Button size="sm" className="hidden sm:inline-flex bg-primary hover:bg-primary/90 text-white shadow-sm hover:shadow">
            Get Started <ArrowRight className="ml-1.5 h-4 w-4" />
          </Button>
        </div>
      </div>
    </nav>
  );
}
