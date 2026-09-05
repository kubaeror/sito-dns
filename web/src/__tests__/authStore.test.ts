import { describe, it, expect, beforeEach } from 'vitest';
import { useAuthStore } from '../stores/authStore';

describe('authStore', () => {
  beforeEach(() => {
    localStorage.clear();
    useAuthStore.getState().clearAuth();
  });

  it('initializes with default unauthenticated state', () => {
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.username).toBeNull();
    expect(state.role).toBeNull();
    expect(state.token).toBeNull();
  });

  it('updates state upon setAuth', () => {
    useAuthStore.getState().setAuth('admin', 'admin', 'dummy-token');
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.username).toBe('admin');
    expect(state.role).toBe('admin');
    expect(state.token).toBe('dummy-token');
  });

  it('persists credentials in localStorage', () => {
    useAuthStore.getState().setAuth('operator', 'operator', 'op-token');
    const raw = localStorage.getItem('sito_auth');
    expect(raw).toBeTruthy();
    const parsed = JSON.parse(raw!);
    expect(parsed.username).toBe('operator');
    expect(parsed.token).toBe('op-token');
  });

  it('clears state upon clearAuth', () => {
    useAuthStore.getState().setAuth('admin', 'admin', 'dummy-token');
    expect(useAuthStore.getState().isAuthenticated).toBe(true);

    useAuthStore.getState().clearAuth();
    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(false);
    expect(state.username).toBeNull();
    expect(state.role).toBeNull();
    expect(state.token).toBeNull();
    expect(localStorage.getItem('sito_auth')).toBeNull();
  });
});
