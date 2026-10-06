import { HTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

export interface BadgeProps extends HTMLAttributes<HTMLDivElement> {
  variant?: "default" | "success" | "warning" | "destructive" | "outline" | "teal";
}

const Badge = forwardRef<HTMLDivElement, BadgeProps>(
  ({ className, variant = "default", ...props }, ref) => {
    return (
      <div
        ref={ref}
        className={cn(
          "inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold tracking-wide transition-colors",
          {
            "border-transparent bg-primary/10 text-primary": variant === "default",
            "border-transparent bg-dashboard-success/10 text-dashboard-success": variant === "success",
            "border-transparent bg-dashboard-warning/10 text-dashboard-warning": variant === "warning",
            "border-transparent bg-dashboard-critical/10 text-dashboard-critical": variant === "destructive",
            "border-transparent bg-dashboard-teal/10 text-dashboard-teal": variant === "teal",
            "text-text-secondary border-border-subtle bg-bg-main": variant === "outline",
          },
          className
        )}
        {...props}
      />
    );
  }
);
Badge.displayName = "Badge";

export { Badge };
