/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        'tl': {
          // Backgrounds
          'bg':        '#0A0F1A',
          'surface':   '#111827',
          'surface2':  '#1F2937',
          'surface3':  '#2D3748',
          // Borders
          'border':    '#374151',
          'border2':   '#4B5563',
          // Text
          'text':      '#F9FAFB',
          'text2':     '#D1D5DB',
          'text3':     '#9CA3AF',
          'muted':     '#6B7280',
          // Accent
          'blue':      '#3B82F6',
          'blue2':     '#1D4ED8',
          'blue-dim':  '#1E3A5F',
          // Severity (constant across themes)
          'critical':  '#EF4444',
          'high':      '#F97316',
          'medium':    '#F59E0B',
          'low':       '#10B981',
          'info':      '#6B7280',
          // Status
          'success':   '#10B981',
          'warning':   '#F59E0B',
          'danger':    '#EF4444',
          'purple':    '#8B5CF6',
        }
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in':    'fadeIn 0.2s ease-out',
        'slide-in':   'slideIn 0.2s ease-out',
      },
      keyframes: {
        fadeIn:  { from: { opacity: '0' },              to: { opacity: '1' } },
        slideIn: { from: { opacity: '0', transform: 'translateY(-4px)' }, to: { opacity: '1', transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
}
