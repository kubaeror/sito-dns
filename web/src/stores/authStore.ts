import { create } from 'zustand';

interface AuthState {
  token: string | null;
  username: string | null;
  role: string | null;
  isAuthenticated: boolean;
  setAuth: (username: string, role: string, token?: string | null) => void;
  clearAuth: () => void;
}

const STORAGE_KEY = 'sito_auth';

function loadInitialState() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        token: parsed.token || null,
        username: parsed.username || null,
        role: parsed.role || null,
        isAuthenticated: true,
      };
    }
  } catch {
    // ignore parse error
  }
  return {
    token: null,
    username: null,
    role: null,
    isAuthenticated: false,
  };
}

const initial = loadInitialState();

export const useAuthStore = create<AuthState>((set) => ({
  token: initial.token,
  username: initial.username,
  role: initial.role,
  isAuthenticated: initial.isAuthenticated,

  setAuth: (username: string, role: string, token?: string | null) => {
    const payload = { username, role, token: token || null };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
    set({
      username,
      role,
      token: token || null,
      isAuthenticated: true,
    });
  },

  clearAuth: () => {
    localStorage.removeItem(STORAGE_KEY);
    set({
      username: null,
      role: null,
      token: null,
      isAuthenticated: false,
    });
  },
}));
