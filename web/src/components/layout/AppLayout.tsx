import React, { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  LayoutDashboard,
  ScrollText,
  ShieldCheck,
  Users,
  Globe,
  Server,
  Settings,
  Cpu,
  Wand2,
  LogOut,
  Sun,
  Moon,
  Laptop,
  Languages,
  Menu,
  X,
  ShieldAlert,
  Shield,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { useAuthStore } from '../../stores/authStore';
import apiClient from '../../api/client';
import type { StatusResponse } from '../../api/types';

export const AppLayout: React.FC = () => {
  const { t, i18n } = useTranslation();
  const { theme, setTheme } = useTheme();
  const { username, role, clearAuth, isAuthenticated } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [status, setStatus] = useState<StatusResponse | null>(null);

  useEffect(() => {
    // Fetch system status to check HA role and connectivity
    let isMounted = true;
    apiClient
      .GET('/api/v1/status')
      .then(({ data }) => {
        if (isMounted && data) {
          setStatus(data);
        }
      })
      .catch(() => {});

    return () => {
      isMounted = false;
    };
  }, [location.pathname]);

  const handleLogout = async () => {
    try {
      await apiClient.POST('/api/v1/auth/logout');
    } catch {
      // ignore
    }
    clearAuth();
    navigate('/login');
  };

  const toggleLanguage = () => {
    const next = i18n.language.startsWith('pl') ? 'en' : 'pl';
    i18n.changeLanguage(next);
  };

  const cycleTheme = () => {
    if (theme === 'light') setTheme('dark');
    else if (theme === 'dark') setTheme('auto');
    else setTheme('light');
  };

  const navItems = [
    { to: '/', label: t('nav.dashboard'), icon: LayoutDashboard },
    { to: '/querylog', label: t('nav.querylog'), icon: ScrollText },
    { to: '/filtering', label: t('nav.filtering'), icon: ShieldCheck },
    { to: '/clients', label: t('nav.clients'), icon: Users },
    { to: '/rewrites', label: t('nav.rewrites'), icon: Globe },
    { to: '/upstreams', label: t('nav.upstreams'), icon: Server },
    { to: '/settings', label: t('nav.settings'), icon: Settings },
    { to: '/system', label: t('nav.system'), icon: Cpu },
    { to: '/wizard', label: t('nav.wizard'), icon: Wand2 },
  ];

  // Determine HA role badge
  const haRole = (status?.role || 'standalone').toLowerCase();
  const isReplica = haRole === 'replica' || haRole === 'slave';
  const isPrimary = haRole === 'primary' || haRole === 'master';

  return (
    <div className="min-h-screen flex flex-col bg-gray-50 dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100">
      {/* Top Navbar */}
      <header className="sticky top-0 z-40 w-full border-b border-gray-200 dark:border-zinc-800 bg-white/80 dark:bg-zinc-900/80 backdrop-blur-md">
        <div className="flex h-16 items-center justify-between px-4 sm:px-6">
          {/* Brand & Mobile toggle */}
          <div className="flex items-center space-x-3">
            <button
              type="button"
              className="lg:hidden p-2 rounded-lg text-zinc-600 dark:text-zinc-400 hover:bg-gray-100 dark:hover:bg-zinc-800"
              onClick={() => setMobileOpen(!mobileOpen)}
              aria-label="Toggle navigation"
            >
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </button>
            <div className="flex items-center space-x-2.5">
              <div className="h-8 w-8 rounded-lg bg-emerald-600 flex items-center justify-center text-white shadow-sm shadow-emerald-600/30">
                <Shield className="h-5 w-5" />
              </div>
              <div className="flex flex-col">
                <span className="font-bold text-lg leading-tight tracking-tight text-zinc-900 dark:text-white">
                  sito<span className="text-emerald-600 dark:text-emerald-400">DNS</span>
                </span>
                {status && (
                  <span className="text-[10px] text-zinc-600 dark:text-zinc-300 font-mono">
                    v{status.version}
                  </span>
                )}
              </div>
            </div>
          </div>

          {/* Center: HA Status Pill */}
          <div className="hidden sm:flex items-center">
            {isReplica ? (
              <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950/70 dark:text-amber-300 border border-amber-300 dark:border-amber-800 animate-pulse">
                <ShieldAlert className="h-3.5 w-3.5" />
                <span>{t('common.read_only_badge')}</span>
              </div>
            ) : isPrimary ? (
              <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/70 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800">
                <span className="h-2 w-2 rounded-full bg-emerald-500 animate-ping" />
                <span>{t('common.primary_badge')}</span>
              </div>
            ) : (
              <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-medium bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300 border border-zinc-300 dark:border-zinc-700">
                <span className="h-2 w-2 rounded-full bg-zinc-400" />
                <span>{t('common.standalone_badge')}</span>
              </div>
            )}
          </div>

          {/* Right actions: Language, Theme, User profile */}
          <div className="flex items-center space-x-2">
            {/* Language toggle */}
            <button
              type="button"
              onClick={toggleLanguage}
              className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-zinc-700 dark:text-zinc-300 hover:bg-gray-100 dark:hover:bg-zinc-800 transition"
              title="Switch Language (English / Polski)"
              aria-label="Switch Language"
            >
              <Languages className="h-4 w-4" />
              <span>{i18n.language.startsWith('pl') ? 'PL' : 'EN'}</span>
            </button>

            {/* Theme toggle */}
            <button
              type="button"
              onClick={cycleTheme}
              className="p-2 rounded-lg text-zinc-700 dark:text-zinc-300 hover:bg-gray-100 dark:hover:bg-zinc-800 transition"
              title={`Theme: ${theme}`}
              aria-label={`Theme: ${theme}`}
            >
              {theme === 'light' ? (
                <Sun className="h-4 w-4 text-amber-500" />
              ) : theme === 'dark' ? (
                <Moon className="h-4 w-4 text-indigo-400" />
              ) : (
                <Laptop className="h-4 w-4 text-zinc-400" />
              )}
            </button>

            {/* User Profile / Logout */}
            <div className="flex items-center pl-2 border-l border-gray-200 dark:border-zinc-800 space-x-2">
              <div className="hidden md:flex flex-col text-right">
                <span className="text-xs font-medium text-zinc-900 dark:text-zinc-100">
                  {username || 'Administrator'}
                </span>
                <span className="text-[10px] text-zinc-600 dark:text-zinc-300 uppercase tracking-wider">
                  {role || 'admin'}
                </span>
              </div>
              {isAuthenticated ? (
                <button
                  type="button"
                  onClick={handleLogout}
                  className="p-2 rounded-lg text-zinc-500 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/50 transition"
                  title={t('nav.logout')}
                  aria-label={t('nav.logout')}
                >
                  <LogOut className="h-4 w-4" />
                </button>
              ) : (
                <NavLink
                  to="/login"
                  className="px-3 py-1.5 text-xs font-medium rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
                >
                  {t('auth.sign_in')}
                </NavLink>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Main Body */}
      <div className="flex flex-1">
        {/* Sidebar for Desktop */}
        <aside className="hidden lg:flex w-64 flex-col border-r border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/50 p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                    isActive
                      ? 'bg-emerald-50 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-400 font-semibold shadow-xs'
                      : 'text-zinc-600 dark:text-zinc-400 hover:bg-gray-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100'
                  }`
                }
              >
                <Icon className="h-4 w-4 shrink-0" />
                <span>{item.label}</span>
              </NavLink>
            );
          })}
        </aside>

        {/* Mobile Navigation Drawer */}
        {mobileOpen && (
          <div className="fixed inset-0 z-50 lg:hidden flex">
            <div
              className="fixed inset-0 bg-black/50 backdrop-blur-xs"
              onClick={() => setMobileOpen(false)}
            />
            <div className="relative w-64 bg-white dark:bg-zinc-900 p-4 flex flex-col space-y-2 z-10">
              <div className="flex items-center justify-between pb-3 border-b border-gray-200 dark:border-zinc-800">
                <span className="font-bold text-lg text-emerald-600">sito DNS</span>
                <button
                  type="button"
                  onClick={() => setMobileOpen(false)}
                  className="p-1 rounded text-zinc-500"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              <nav className="flex flex-col space-y-1 pt-2">
                {navItems.map((item) => {
                  const Icon = item.icon;
                  return (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === '/'}
                      onClick={() => setMobileOpen(false)}
                      className={({ isActive }) =>
                        `flex items-center space-x-3 px-3 py-2.5 rounded-lg text-sm font-medium transition ${
                          isActive
                            ? 'bg-emerald-50 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400 font-semibold'
                            : 'text-zinc-600 dark:text-zinc-400 hover:bg-gray-100 dark:hover:bg-zinc-800'
                        }`
                      }
                    >
                      <Icon className="h-4 w-4 shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  );
                })}
              </nav>
            </div>
          </div>
        )}

        {/* Main Content Viewport */}
        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl mx-auto w-full">
          <Outlet />
        </main>
      </div>
    </div>
  );
};
