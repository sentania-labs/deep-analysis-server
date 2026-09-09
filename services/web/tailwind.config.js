// Tailwind build config for the web service (issue #126).
//
// This is the theme that base.html used to hand to the Tailwind play CDN at
// runtime. The CDN is gone (it needed 'unsafe-eval' and a third-party script
// origin in the CSP), so the stylesheet is compiled ahead of time into
// web_service/static/css/tailwind.css and committed. Rebuild it with
// `bash services/web/build-css.sh` after editing any template, JS file, or
// this config; CI's frontend-assets job fails when the committed file drifts.
module.exports = {
  content: [
    "./web_service/templates/**/*.html",
    "./web_service/static/js/**/*.js",
    "./web_service/**/*.py",
  ],
  darkMode: "class",
  // Classes assembled from Jinja variables (text-{{ col.align }}) never
  // appear verbatim in a template, so keep them out of the content scan.
  safelist: ["text-left", "text-right", "text-center"],
  theme: {
    extend: {
      colors: {
        base: { DEFAULT: "#0a0a0f", light: "#f4f4f8" },
        surface: {
          DEFAULT: "#12121a",
          2: "#1a1a24",
          3: "#22222e",
          light: "#ffffff",
          "light-2": "#f9f9fb",
          "light-3": "#eeeef2",
        },
        border: {
          DEFAULT: "#2a2a36",
          subtle: "#1e1e28",
          focus: "#4e7cff",
          light: "#dcdce4",
        },
        txt: {
          primary: "#e8e8ed",
          secondary: "#8b8b9e",
          tertiary: "#5c5c6e",
          "primary-light": "#1a1a2e",
          "secondary-light": "#6b6b7e",
        },
        accent: { DEFAULT: "#4e7cff", hover: "#6690ff", muted: "rgba(78,124,255,0.1)" },
        success: { DEFAULT: "#22c55e", muted: "rgba(34,197,94,0.1)" },
        danger: { DEFAULT: "#ef4444", muted: "rgba(239,68,68,0.1)" },
        warning: { DEFAULT: "#eab308", muted: "rgba(234,179,8,0.1)" },
        mtg: {
          white: "#f9e4b7",
          blue: "#5b8def",
          black: "#9b8ec2",
          red: "#e05555",
          green: "#3bb55a",
        },
      },
      fontFamily: {
        ui: ["Inter", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "Fira Code", "monospace"],
      },
    },
  },
  plugins: [],
};
