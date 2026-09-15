import type { Config } from 'tailwindcss';

/*
 * Design tokens aligned with AssetManagment_Front:
 * navy dark-* ramp, gray muted text, teal primary brand.
 * `surface.*` / `fg.*` still resolve via CSS variables in globals.css
 * so light/dark theme flipping keeps working.
 */
const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
    '../../packages/ui/src/**/*.{js,ts,jsx,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        // AssetManagement navy / gray / teal / accent maps
        dark: {
          '10': '#1F2533',
          '20': '#1F2638',
          '30': '#192130',
          '40': '#1E2434',
          '50': '#151D2C',
          '60': '#181E2D',
          '70': '#161B28',
          '80': '#121724',
        },
        amgray: {
          '10': '#FFFEFE',
          '20': '#9298A2',
          '30': '#909FAE',
          '40': '#728497',
          '50': '#596272',
          '60': '#333A47',
        },
        teal: {
          '10': '#6AF8E7',
          '20': '#4FD2C2',
          '30': '#3AC7B6',
        },
        // Primary brand — remapped from blue → teal so existing
        // `brand-*` utilities pick up the AssetManagement accent.
        brand: {
          50: '#e6fffb',
          100: '#c2fff7',
          200: '#8af8ea',
          300: '#6AF8E7',
          400: '#5FEEDD',
          500: '#4FD2C2',
          600: '#3AC7B6',
          700: '#2a9e91',
          800: '#1f766c',
          900: '#15554e',
        },
        surface: {
          base: 'var(--surface-base)',
          raised: 'var(--surface-raised)',
          card: 'var(--surface-card)',
          hover: 'var(--surface-hover)',
          subtle: 'var(--surface-subtle)',
          border: 'var(--surface-border)',
          divider: 'var(--surface-divider)',
        },
        fg: {
          primary: 'var(--fg-primary)',
          secondary: 'var(--fg-secondary)',
          muted: 'var(--fg-muted)',
          subtle: 'var(--fg-subtle)',
          inverse: 'var(--fg-inverse)',
        },
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#eab308',
          low: '#3163CF',
          info: '#64FF99',
        },
        status: {
          live: '#64FF99',
          warn: '#F0BC56',
          dead: '#ef4444',
          idle: '#596272',
        },
        landing: {
          accent: {
            ember: '#F0BC56',
            violet: '#3163CF',
          },
        },
        // Marketing namespace — navy/teal (kept as `velvet.*` for API stability)
        velvet: {
          emerald: '#0d4f48',
          'emerald-light': '#1a6b62',
          'emerald-mint': '#6AF8E7',
          ruby: '#9F1239',
          'ruby-light': '#BE123C',
          'ruby-soft': '#FB7185',
          sapphire: '#3163CF',
          'sapphire-soft': '#4FD2C2',
          'sapphire-softer': '#6AF8E7',
          'surface-base': '#121724',
          'surface-raised': '#161B28',
          'surface-sunken': '#0E121C',
          'surface-overlay': '#1F2638',
          'content-primary': '#FFFEFE',
          'content-secondary': '#9298A2',
          'content-tertiary': '#596272',
          border: 'rgba(55, 65, 81, 0.85)',
          'border-strong': '#374151',
          success: '#64FF99',
          warning: '#F0BC56',
          error: '#FB7185',
          info: '#4FD2C2',
        },
      },
      backgroundImage: {
        'landing-grad-hero': 'var(--landing-grad-hero)',
        'landing-grad-pillars': 'var(--landing-grad-pillars)',
        'landing-grad-cta': 'var(--landing-grad-cta)',
        'velvet-emerald-cta': 'linear-gradient(135deg, #4FD2C2 0%, #3AC7B6 100%)',
        'velvet-ruby-cta': 'linear-gradient(135deg, #9F1239 0%, #BE123C 100%)',
        'velvet-sapphire-soft': 'linear-gradient(135deg, #3163CF 0%, #4FD2C2 100%)',
        'velvet-hero-grad':
          'radial-gradient(ellipse at top, rgba(79,210,194,0.28) 0%, rgba(18,23,36,0) 60%), linear-gradient(180deg, #121724 0%, #0E121C 100%)',
        'velvet-pillars-grad':
          'linear-gradient(135deg, rgba(79,210,194,0.16) 0%, rgba(49,99,207,0.16) 100%)',
        'velvet-cta-grad':
          'radial-gradient(ellipse at center, rgba(79,210,194,0.22) 0%, rgba(18,23,36,0) 70%), linear-gradient(135deg, #0E121C 0%, #121724 100%)',
      },
      boxShadow: {
        'glow-emerald-sm': '0 0 8px rgba(79, 210, 194, 0.30)',
        'glow-emerald-md': '0 0 20px rgba(79, 210, 194, 0.40)',
        'glow-emerald-lg': '0 0 36px rgba(106, 248, 231, 0.25)',
        'glow-ruby-sm': '0 0 8px rgba(159, 18, 57, 0.30)',
        'glow-ruby-md': '0 0 20px rgba(159, 18, 57, 0.40)',
        'glow-sapphire-sm': '0 0 8px rgba(49, 99, 207, 0.30)',
        'glow-sapphire-md': '0 0 20px rgba(49, 99, 207, 0.40)',
        'glow-teal': '0 4px 16px rgba(79, 210, 195, 0.16)',
      },
      borderRadius: {
        am: '6px',
        'am-lg': '10px',
        'am-pill': '32px',
      },
      transitionTimingFunction: {
        'landing-out-expo': 'cubic-bezier(0.16, 1, 0.3, 1)',
        'landing-out-quart': 'cubic-bezier(0.25, 1, 0.5, 1)',
        'landing-in-out-quad': 'cubic-bezier(0.45, 0, 0.55, 1)',
      },
      fontFamily: {
        sans: [
          'Gilroy',
          'Gilory-Regular',
          'var(--font-inter)',
          'Helvetica',
          'system-ui',
          'sans-serif',
        ],
        // Prefer `font-gilroy-*` — do not shadow Tailwind's font-weight
        // utilities (`font-medium` / `font-semibold` / `font-bold`).
        'gilroy-medium': ['Gilory-Medium', 'Gilroy', 'system-ui', 'sans-serif'],
        'gilroy-semibold': ['Gilory-Semibold', 'Gilroy', 'system-ui', 'sans-serif'],
        'gilroy-bold': ['Gilory-Bold', 'Gilroy', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
        'velvet-display': [
          'Gilory-Bold',
          'Gilroy',
          'var(--font-velvet-display)',
          'ui-serif',
          'Georgia',
          'serif',
        ],
        'velvet-body': [
          'Gilroy',
          'Gilory-Regular',
          'var(--font-velvet-body)',
          'system-ui',
          'sans-serif',
        ],
        'velvet-mono': [
          'var(--font-velvet-mono)',
          'ui-monospace',
          'SFMono-Regular',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
};

export default config;
