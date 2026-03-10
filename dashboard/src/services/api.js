import axios from 'axios';

const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
  timeout: 10000,
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('auth_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('auth_token');
    }
    return Promise.reject(error);
  }
);

export const getStats = () => api.get('/dashboard/stats').then((r) => r.data);

export const getThreats = (params = {}) =>
  api.get('/threats', { params }).then((r) => r.data);

export const getAgents = () => api.get('/agents').then((r) => r.data);

export const getTimeline = (params = {}) =>
  api.get('/dashboard/timeline', { params }).then((r) => r.data);

// No dedicated intel endpoint yet — callers fall back to mock data on 404.
export const getThreatIntel = () =>
  api.get('/intel').then((r) => r.data);

export const updateThreatStatus = (threatId, status) =>
  api.patch(`/threats/${threatId}/status`, { status }).then((r) => r.data);

export default api;
