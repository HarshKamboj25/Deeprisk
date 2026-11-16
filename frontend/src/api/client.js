import axios from 'axios'

const DEFAULT_API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000'

const STORAGE_KEY = 'deprisk_api_base_url'

function normalizeApiBaseUrl(value) {
  const trimmed = value.trim().replace(/\/+$/, '')

  if (!trimmed) {
    throw new Error('API URL cannot be empty.')
  }

  let parsed

  try {
    parsed = new URL(trimmed)
  } catch {
    throw new Error('Enter a valid API URL.')
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('API URL must use HTTP or HTTPS.')
  }

  if (parsed.username || parsed.password) {
    throw new Error('Credentials must not be included in the API URL.')
  }

  return trimmed
}

function getInitialApiBaseUrl() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY)
    return saved ? normalizeApiBaseUrl(saved) : DEFAULT_API_BASE_URL
  } catch {
    return DEFAULT_API_BASE_URL
  }
}

const api = axios.create({
  baseURL: getInitialApiBaseUrl(),
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

export function getApiBaseUrl() {
  return api.defaults.baseURL
}

export function setApiBaseUrl(value) {
  const normalized = normalizeApiBaseUrl(value)

  try {
    localStorage.setItem(STORAGE_KEY, normalized)
  } catch {
    throw new Error('Unable to save API URL in browser storage.')
  }

  api.defaults.baseURL = normalized
  return normalized
}

export function resetApiBaseUrl() {
  try {
    localStorage.removeItem(STORAGE_KEY)
  } catch {
    throw new Error('Unable to reset API URL preference.')
  }

  api.defaults.baseURL = DEFAULT_API_BASE_URL
  return DEFAULT_API_BASE_URL
}

export async function checkApiHealth() {
  const response = await api.get('/health')
  return response.data
}

export async function checkApiReadiness() {
  const response = await api.get('/health/ready')
  return response.data
}

export async function getApiConfiguration() {
  const response = await api.get('/api/v1/configuration')
  return response.data
}

export async function submitScan(payload) {
  const response = await api.post('/api/v1/scans', payload)
  return response.data
}

export async function getScanStatus(scanId) {
  const response = await api.get(`/api/v1/scans/${scanId}`)
  return response.data
}

export async function getScanReport(scanId) {
  const response = await api.get(`/api/v1/scans/${scanId}/report`)
  return response.data
}

export async function getRepositories() {
  const response = await api.get('/api/v1/repositories')
  return response.data
}

export async function getScanHistory(params = {}) {
  const response = await api.get('/api/v1/scans', { params })
  return response.data
}

export default api