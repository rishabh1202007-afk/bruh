import { ButtonHTMLAttributes, forwardRef } from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "outline" | "ghost";
  size?: "sm" | "md" | "lg";
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", size = "md", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center rounded-[12px] font-medium transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 disabled:opacity-50 disabled:pointer-events-none ring-offset-bg-main duration-200",
          {
            "bg-gradient-to-r from-primary to-secondary text-white hover:shadow-md shadow-sm shadow-primary/20":
              variant === "primary",
            "bg-bg-white text-text-primary hover:bg-gray-50 shadow-sm border border-border-subtle":
              variant === "secondary",
            "border border-border-subtle hover:bg-gray-50 hover:text-text-primary text-text-secondary":
              variant === "outline",
            "hover:bg-gray-50 text-text-secondary hover:text-text-primary": variant === "ghost",
            "h-9 px-4 text-sm": size === "sm",
            "h-11 px-6 py-2 text-sm": size === "md",
            "h-14 px-8 text-base": size === "lg",
          },
          className
        )}
        {...props}
      />
    );
  }
);

Button.displayName = "Button";
export { Button };
