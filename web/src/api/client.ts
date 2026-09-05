import createClient, { type Middleware } from 'openapi-fetch';
import type { paths } from './schema';
import { useAuthStore } from '../stores/authStore';

export const apiClient = createClient<paths>({
  baseUrl: '',
  headers: {
    'Content-Type': 'application/json',
  },
});

const authMiddleware: Middleware = {
  onRequest({ request }) {
    const token = useAuthStore.getState().token;
    if (token) {
      request.headers.set('Authorization', `Bearer ${token}`);
    }
    // Also include credentials for cookie-based session
    (request as RequestInit).credentials = 'include';
    return request;
  },
  onResponse({ response }) {
    if (response.status === 401) {
      // If we received 401 on an authenticated endpoint and have stored credentials, clear session
      const isLoginEndpoint = response.url.includes('/api/v1/auth/login');
      if (!isLoginEndpoint && useAuthStore.getState().isAuthenticated) {
        useAuthStore.getState().clearAuth();
      }
    }
    return response;
  },
};

apiClient.use(authMiddleware);

export default apiClient;
