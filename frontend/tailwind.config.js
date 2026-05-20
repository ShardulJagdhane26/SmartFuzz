
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
        mono: ['"JetBrains Mono"', 'monospace'],
      },
      boxShadow: {
        'soft': '0 20px 25px -5px rgba(79, 70, 229, 0.05), 0 8px 10px -6px rgba(79, 70, 229, 0.05)',
      }
    },
  },
  plugins: [],
}
