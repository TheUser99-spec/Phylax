/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        bg: '#050709',
        surface: '#0a0f14',
        border: '#1a2530',
        'accent-green': '#00ff88',
        'accent-blue': '#00c4ff',
        red: '#ff3355',
        'text-primary': '#e8f0f7',
        'text-muted': '#3d5566',
        'text-dim': '#1f3040',
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['Space Mono', 'monospace'],
      },
    },
  },
  plugins: [],
}
