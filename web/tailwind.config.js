/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        background: "#0a0b10",
        primary: "#8b5cf6",
        secondary: "#06b6d4",
        accent: "#9ef01a",
        muted: "#94a3b8",
        sev: {
          critical: "#fca5a5",
          high: "#fdba74",
          medium: "#fde047",
          low: "#93c5fd",
          info: "#94a3b8",
        },
      },
      fontFamily: {
        sans: ["Outfit", "ui-sans-serif", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
}
