/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        'defense-dark': '#0f172a',
        'defense-card': '#1e293b',
        'defense-accent': '#38bdf8',
        'defense-block': '#ef4444',
        'defense-allow': '#22c55e',
      }
    },
  },
  plugins: [],
}