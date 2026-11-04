import type { Config } from "tailwindcss";

const v = (name: string) => `var(--${name})`;

export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}", "../packages/ui/src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        surface: v("surface"),
        raised: v("surface-raised"),
        line: v("border"),
        "line-input": v("border-input"),
        fg: v("text"),
        muted: v("text-muted"),
        silver: v("silver"),
        "silver-strong": v("silver-strong"),
        primary: v("primary"),
        "primary-fg": v("primary-text"),
        danger: v("danger"),
        warning: v("warning"),
        success: v("success"),
      },
      fontFamily: { sans: [v("font-ui")], mono: [v("font-mono")] },
      borderRadius: { sm: v("radius-sm"), DEFAULT: v("radius"), lg: v("radius-lg") },
      boxShadow: { modal: v("shadow-modal") },
      transitionTimingFunction: { out: "cubic-bezier(0.16, 1, 0.3, 1)" },
    },
  },
  plugins: [],
} satisfies Config;
