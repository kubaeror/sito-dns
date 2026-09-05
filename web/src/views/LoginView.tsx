import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { notifications } from '@mantine/notifications';
import { Shield, KeyRound, ArrowRight, Lock } from 'lucide-react';
import apiClient from '../api/client';
import { useAuthStore } from '../stores/authStore';

export const LoginView: React.FC = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [totpRequired, setTotpRequired] = useState(false);
  const [partialToken, setPartialToken] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);

    try {
      if (totpRequired) {
        // Verify TOTP
        const res = await apiClient.POST('/api/v1/auth/totp/verify', {
          body: {
            partial_token: partialToken,
            code: totpCode,
          },
        });

        if (res.error || !res.data) {
          notifications.show({
            title: t('common.error'),
            message: t('auth.invalid_totp'),
            color: 'red',
          });
          setIsLoading(false);
          return;
        }

        const data = res.data;
        setAuth(data.username || username, data.role || 'admin', data.session_id);
        navigate('/');
      } else {
        // Initial login with { user, pass } per OpenAPI contract
        const res = await apiClient.POST('/api/v1/auth/login', {
          body: {
            user: username.trim(),
            pass: password,
          },
        });

        if (res.error || !res.data) {
          notifications.show({
            title: t('common.error'),
            message: t('auth.invalid_credentials'),
            color: 'red',
          });
          setIsLoading(false);
          return;
        }

        const data = res.data;
        if (data.totp_required && data.partial_token) {
          setTotpRequired(true);
          setPartialToken(data.partial_token);
        } else {
          setAuth(data.username || username, data.role || 'admin', data.session_id);
          navigate('/');
        }
      }
    } catch {
      notifications.show({
        title: t('common.error'),
        message: 'Authentication request failed',
        color: 'red',
      });
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col justify-center items-center py-12 px-4 sm:px-6 lg:px-8 bg-gray-50 dark:bg-zinc-950">
      <div className="w-full max-w-md space-y-8">
        <div className="text-center">
          <div className="mx-auto h-12 w-12 rounded-xl bg-emerald-600 flex items-center justify-center text-white shadow-md shadow-emerald-600/30">
            <Shield className="h-7 w-7" />
          </div>
          <h1 className="mt-4 text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-white">
            {t('auth.login_title')}
          </h1>
          <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
            {t('auth.login_subtitle')}
          </p>
        </div>

        <div className="rounded-2xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-8 shadow-sm">
          <form onSubmit={handleLogin} className="space-y-4">
            {!totpRequired ? (
              <>
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('auth.username')}
                  </label>
                  <input
                    type="text"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('auth.password')}
                  </label>
                  <input
                    type="password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>

                <button
                  type="submit"
                  disabled={isLoading}
                  className="w-full inline-flex items-center justify-center space-x-2 py-2.5 px-4 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition shadow-xs"
                >
                  <Lock className="h-3.5 w-3.5" />
                  <span>{isLoading ? t('auth.signing_in') : t('auth.sign_in')}</span>
                </button>
              </>
            ) : (
              <>
                <div className="p-3 rounded-lg bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-800 text-xs text-emerald-800 dark:text-emerald-300 flex items-start space-x-2">
                  <KeyRound className="h-4 w-4 shrink-0 mt-0.5 text-emerald-600" />
                  <p>{t('auth.totp_prompt')}</p>
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1 text-center">
                    {t('auth.totp_code')}
                  </label>
                  <input
                    type="text"
                    required
                    maxLength={6}
                    autoFocus
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    placeholder="123456"
                    className="w-full px-3 py-3 text-center text-xl font-mono tracking-widest rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>

                <button
                  type="submit"
                  disabled={totpCode.length !== 6 || isLoading}
                  className="w-full inline-flex items-center justify-center space-x-2 py-2.5 px-4 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
                >
                  <span>{t('auth.verify_totp')}</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </button>
              </>
            )}
          </form>
        </div>
      </div>
    </div>
  );
};
