import axios from 'axios'

export function getBaseApiUrl(): string {
  try {
    const saved = localStorage.getItem('tl-api-url')
    if (saved) return saved.replace(/\/+$/, '')
  } catch {}
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL.replace(/\/+$/, '')
  }
  if (typeof window !== 'undefined' && window.location.hostname.includes('onrender.com')) {
    return 'https://threatlens-tdpd.onrender.com'
  }
  return ''
}

const initialBase = getBaseApiUrl()
export const api = axios.create({
  baseURL: initialBase ? `${initialBase}/api/v1` : '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 60_000,
})

api.interceptors.request.use((config) => {
  const base = getBaseApiUrl()
  config.baseURL = base ? `${base}/api/v1` : '/api/v1'
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const message =
      err.response?.data?.detail ||
      err.response?.data?.message ||
      err.message ||
      'An unexpected error occurred.'
    return Promise.reject(new Error(message))
  },
)
