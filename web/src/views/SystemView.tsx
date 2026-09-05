import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { notifications } from '@mantine/notifications';
import {
  Download,
  Upload,
  Trash2,
  Key,
  ShieldAlert,
  Copy,
  Check,
  ExternalLink,
  Info,
  Zap,
} from 'lucide-react';
import apiClient from '../api/client';
import { useAuthStore } from '../stores/authStore';
import type {
  CreateTokenResponse,
  TotpSetupResponse,
  RestorePreparedResponse,
} from '../api/types';

export const SystemView: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const navigate = useNavigate();
  const clearAuth = useAuthStore((s) => s.clearAuth);

  // Invalidate domain cache input
  const [invalidateDomain, setInvalidateDomain] = useState('');

  // Token creation modal
  const [createTokenOpen, setCreateTokenOpen] = useState(false);
  const [newTokenName, setNewTokenName] = useState('');
  const [newTokenScope, setNewTokenScope] = useState<'admin' | 'operator' | 'viewer'>('viewer');
  const [createdTokenResult, setCreatedTokenResult] = useState<CreateTokenResponse | null>(null);

  // TOTP setup modal
  const [totpModalOpen, setTotpModalOpen] = useState(false);
  const [totpSetupData, setTotpSetupData] = useState<TotpSetupResponse | null>(null);
  const [totpVerificationCode, setTotpVerificationCode] = useState('');

  // Restore backup modal
  const [restoreModalOpen, setRestoreModalOpen] = useState(false);
  const [restorePrepared, setRestorePrepared] = useState<RestorePreparedResponse | null>(null);

  // Query: System Status
  const { data: status } = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/status');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Query: API Tokens
  const { data: tokens, isLoading: isTokensLoading } = useQuery({
    queryKey: ['api-tokens'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/auth/tokens');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Mutation: Flush Cache
  const flushCacheMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/cache/flush');
      if (res.error || !res.data) throw res.error || new Error('Flush failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: t('system.cache_flushed'),
        color: 'teal',
      });
    },
  });

  // Mutation: Invalidate Domain Cache
  const invalidateDomainMutation = useMutation({
    mutationFn: async (domain: string) => {
      const res = await apiClient.POST('/api/v1/cache/invalidate', {
        params: { query: { domain } },
      });
      if (res.error || !res.data) throw res.error || new Error('Invalidate failed');
      return res.data;
    },
    onSuccess: (_, domain) => {
      notifications.show({
        title: t('common.success'),
        message: `Cache invalidated for ${domain}`,
        color: 'teal',
      });
      setInvalidateDomain('');
    },
  });

  // Mutation: Create Token
  const createTokenMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/auth/tokens', {
        body: {
          name: newTokenName.trim(),
          scope: newTokenScope,
        },
      });
      if (res.error || !res.data) throw res.error || new Error('Create token failed');
      return res.data;
    },
    onSuccess: (data) => {
      setCreatedTokenResult(data);
      setNewTokenName('');
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
  });

  // Mutation: Delete Token
  const deleteTokenMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiClient.DELETE('/api/v1/auth/tokens/{id}', {
        params: { path: { id } },
      });
      if (res.error || !res.data) throw res.error || new Error('Delete token failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'API token revoked',
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['api-tokens'] });
    },
  });

  // Mutation: Start TOTP Setup
  const startTotpSetupMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.GET('/api/v1/auth/totp/setup');
      if (res.error || !res.data) throw res.error || new Error('Setup TOTP failed');
      return res.data;
    },
    onSuccess: (data) => {
      setTotpSetupData(data);
      setTotpModalOpen(true);
    },
  });

  // Mutation: Confirm & Enable TOTP
  const enableTotpMutation = useMutation({
    mutationFn: async (code: string) => {
      const res = await apiClient.POST('/api/v1/auth/totp/enable', {
        body: { code },
      });
      if (res.error || !res.data) throw res.error || new Error('Enable TOTP failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Two-factor authentication enabled successfully',
        color: 'teal',
      });
      setTotpModalOpen(false);
      setTotpSetupData(null);
      setTotpVerificationCode('');
    },
  });

  // Mutation: Disable TOTP
  const disableTotpMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/auth/totp/disable');
      if (res.error || !res.data) throw res.error || new Error('Disable failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Two-factor authentication disabled',
        color: 'teal',
      });
    },
  });

  const handleDownloadBackup = async () => {
    try {
      const res = await fetch('/api/v1/config/backup', {
        headers: {
          ...(useAuthStore.getState().token
            ? { Authorization: `Bearer ${useAuthStore.getState().token}` }
            : {}),
        },
        credentials: 'include',
      });
      if (!res.ok) throw new Error('Backup failed');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `sito-backup-${new Date().toISOString().slice(0, 10)}.tar.gz`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      notifications.show({
        title: t('common.error'),
        message: 'Failed to download backup archive',
        color: 'red',
      });
    }
  };

  const handleUploadBackup = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const arrayBuffer = await file.arrayBuffer();
      const res = await fetch('/api/v1/config/restore', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/gzip',
          ...(useAuthStore.getState().token
            ? { Authorization: `Bearer ${useAuthStore.getState().token}` }
            : {}),
        },
        credentials: 'include',
        body: arrayBuffer,
      });

      if (!res.ok) {
        throw new Error('Restore preparation failed');
      }

      const data: RestorePreparedResponse = await res.json();
      setRestorePrepared(data);
      setRestoreModalOpen(true);
    } catch (err: unknown) {
      notifications.show({
        title: t('common.error'),
        message: (err as Error).message || 'Invalid backup archive',
        color: 'red',
      });
    }
  };

  const confirmRestoreMutation = useMutation({
    mutationFn: async (confirmationToken: string) => {
      const res = await apiClient.POST('/api/v1/config/restore/confirm', {
        body: { confirmation_token: confirmationToken },
      });
      if (res.error || !res.data) throw res.error || new Error('Confirm restore failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Backup restored! Logging out and reloading...',
        color: 'teal',
      });
      clearAuth();
      setTimeout(() => {
        navigate('/login');
        window.location.reload();
      }, 1500);
    },
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
          {t('system.title')}
        </h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400">
          {t('system.subtitle')}
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
            <Zap className="h-4 w-4 text-emerald-500" />
            <span>{t('system.cache_section')}</span>
          </h2>
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            {t('system.cache_desc')}
          </p>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 pt-2">
            <button
              type="button"
              onClick={() => flushCacheMutation.mutate()}
              disabled={flushCacheMutation.isPending}
              className="inline-flex items-center justify-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>{t('system.flush_cache_btn')}</span>
            </button>

            <div className="flex-1 flex items-center space-x-2">
              <input
                type="text"
                value={invalidateDomain}
                onChange={(e) => setInvalidateDomain(e.target.value)}
                placeholder="Invalidate specific domain..."
                className="flex-1 px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
              />
              <button
                type="button"
                onClick={() => {
                  if (invalidateDomain.trim()) {
                    invalidateDomainMutation.mutate(invalidateDomain.trim());
                  }
                }}
                disabled={!invalidateDomain.trim() || invalidateDomainMutation.isPending}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-zinc-800 dark:bg-zinc-700 text-white hover:bg-zinc-700"
              >
                Clear
              </button>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
            <Download className="h-4 w-4 text-emerald-500" />
            <span>{t('system.backup_section')}</span>
          </h2>
          <p className="text-xs text-zinc-500 dark:text-zinc-400">
            {t('system.backup_desc')}
          </p>

          <div className="flex items-center space-x-3 pt-2">
            <button
              type="button"
              onClick={handleDownloadBackup}
              className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 hover:bg-gray-50 dark:hover:bg-zinc-700 transition"
            >
              <Download className="h-3.5 w-3.5 text-emerald-500" />
              <span>{t('system.download_backup')}</span>
            </button>

            <label className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-zinc-800 dark:bg-zinc-700 text-white hover:bg-zinc-700 cursor-pointer transition">
              <Upload className="h-3.5 w-3.5 text-emerald-400" />
              <span>{t('system.restore_backup')}</span>
              <input
                type="file"
                accept=".tar.gz,.tgz"
                onChange={handleUploadBackup}
                className="hidden"
              />
            </label>
          </div>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
        <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
          <Check className="h-4 w-4 text-emerald-500" />
          <span>{t('system.totp_section')}</span>
        </h2>
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          {t('system.totp_status_disabled')}
        </p>

        <div className="flex items-center space-x-3 pt-2">
          <button
            type="button"
            onClick={() => startTotpSetupMutation.mutate()}
            disabled={startTotpSetupMutation.isPending}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
          >
            <span>{t('system.setup_totp_btn')}</span>
          </button>

          <button
            type="button"
            onClick={() => {
              if (window.confirm('Disable two-factor authentication?')) {
                disableTotpMutation.mutate();
              }
            }}
            className="inline-flex items-center space-x-1 px-3 py-2 text-xs font-medium rounded-lg text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/40 transition"
          >
            <span>{t('system.disable_totp_btn')}</span>
          </button>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
              <Key className="h-4 w-4 text-emerald-500" />
              <span>{t('system.tokens_section')}</span>
            </h2>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
              {t('system.tokens_desc')}
            </p>
          </div>
          <button
            type="button"
            onClick={() => {
              setCreatedTokenResult(null);
              setCreateTokenOpen(true);
            }}
            className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
          >
            <Key className="h-3.5 w-3.5" />
            <span>{t('system.create_token_btn')}</span>
          </button>
        </div>

        <div className="rounded-lg border border-gray-200 dark:border-zinc-800 overflow-hidden">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50/70 dark:bg-zinc-900/70 font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              <tr>
                <th className="py-2.5 px-4">{t('common.name')}</th>
                <th className="py-2.5 px-4">Scope</th>
                <th className="py-2.5 px-4">Created</th>
                <th className="py-2.5 px-4 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
              {isTokensLoading ? (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-zinc-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : tokens && tokens.length > 0 ? (
                tokens.map((tok) => (
                  <tr key={tok.id} className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/40">
                    <td className="py-2.5 px-4 font-semibold text-zinc-900 dark:text-white">
                      {tok.name}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 uppercase">
                        {tok.scope}
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-zinc-500">
                      {new Date(tok.created_at * 1000).toLocaleDateString()}
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          if (window.confirm(`Revoke token '${tok.name}'?`)) {
                            deleteTokenMutation.mutate(tok.id);
                          }
                        }}
                        className="p-1 rounded text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="py-6 text-center text-zinc-400">
                    {t('system.no_tokens')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-3">
        <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
          <Info className="h-4 w-4 text-emerald-500" />
          <span>{t('system.system_info_section')}</span>
        </h2>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs pt-2">
          <div>
            <span className="text-zinc-500 block">{t('system.sys_version')}</span>
            <span className="font-mono font-bold text-zinc-900 dark:text-white">
              v{status?.version || '0.1.0'}
            </span>
          </div>
          <div>
            <span className="text-zinc-500 block">{t('system.sys_license')}</span>
            <span className="font-medium text-zinc-900 dark:text-white">GPL-3.0-only</span>
          </div>
          <div>
            <span className="text-zinc-500 block">{t('system.sys_repo')}</span>
            <a
              href="https://github.com/kubaeror/sito-dns"
              target="_blank"
              rel="noreferrer"
              className="font-medium text-emerald-600 dark:text-emerald-400 hover:underline flex items-center space-x-1"
            >
              <span>GitHub</span>
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
          <div>
            <span className="text-zinc-500 block">Stack</span>
            <span className="font-medium text-zinc-900 dark:text-white">Rust + React 18 SPA</span>
          </div>
        </div>
      </div>

      {createTokenOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4">
            {createdTokenResult ? (
              <div className="space-y-4">
                <h2 className="text-lg font-bold text-emerald-600 flex items-center space-x-2">
                  <Check className="h-5 w-5" />
                  <span>{t('system.token_created_modal_title')}</span>
                </h2>
                <div className="p-3 rounded-lg bg-amber-50 dark:bg-amber-950/50 border border-amber-300 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-300">
                  {t('system.token_created_warning')}
                </div>
                <div className="p-3 rounded-lg bg-zinc-950 font-mono text-xs text-emerald-400 break-all flex items-center justify-between">
                  <span>{createdTokenResult.token}</span>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(createdTokenResult.token);
                      notifications.show({ message: t('common.copied'), color: 'teal' });
                    }}
                    className="p-1 rounded text-zinc-400 hover:text-white shrink-0 ml-2"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                </div>
                <div className="pt-2 flex justify-end">
                  <button
                    type="button"
                    onClick={() => {
                      setCreateTokenOpen(false);
                      setCreatedTokenResult(null);
                    }}
                    className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700"
                  >
                    {t('common.close')}
                  </button>
                </div>
              </div>
            ) : (
              <div className="space-y-4">
                <h2 className="text-lg font-bold text-zinc-900 dark:text-white">
                  {t('system.create_token_btn')}
                </h2>
                <div className="space-y-3">
                  <div>
                    <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                      {t('system.token_name_label')}
                    </label>
                    <input
                      type="text"
                      value={newTokenName}
                      onChange={(e) => setNewTokenName(e.target.value)}
                      placeholder="e.g. Prometheus Collector, Home Assistant"
                      className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                      {t('system.token_scope_label')}
                    </label>
                    <select
                      value={newTokenScope}
                      onChange={(e) => setNewTokenScope(e.target.value as 'admin' | 'operator' | 'viewer')}
                      className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                    >
                      <option value="viewer">Viewer (Read-only stats and querylog)</option>
                      <option value="operator">Operator (Filtering rules, cache, upstreams)</option>
                      <option value="admin">Admin (Full administrative privileges)</option>
                    </select>
                  </div>
                </div>

                <div className="flex items-center justify-end space-x-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setCreateTokenOpen(false)}
                    className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
                  >
                    {t('common.cancel')}
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      if (newTokenName.trim()) {
                        createTokenMutation.mutate();
                      }
                    }}
                    disabled={!newTokenName.trim() || createTokenMutation.isPending}
                    className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
                  >
                    {t('common.create')}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {totpModalOpen && totpSetupData && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4 max-h-[90vh] overflow-y-auto">
            <h2 className="text-lg font-bold text-zinc-900 dark:text-white">
              {t('system.totp_modal_title')}
            </h2>
            <p className="text-xs text-zinc-500">
              {t('system.totp_scan_desc')}
            </p>

            <div className="flex justify-center p-4 bg-white rounded-xl">
              {totpSetupData.qr_code.startsWith('data:image') ? (
                <img
                  src={totpSetupData.qr_code}
                  alt="TOTP QR Code"
                  className="h-44 w-44"
                />
              ) : (
                <div
                  dangerouslySetInnerHTML={{ __html: totpSetupData.qr_code }}
                  className="h-44 w-44 flex items-center justify-center"
                />
              )}
            </div>

            <div>
              <span className="block text-xs text-zinc-500 mb-1">{t('system.totp_manual_secret')}</span>
              <div className="p-2 rounded-lg bg-zinc-100 dark:bg-zinc-800 font-mono text-xs flex items-center justify-between">
                <span>{totpSetupData.secret}</span>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(totpSetupData.secret);
                    notifications.show({ message: t('common.copied'), color: 'teal' });
                  }}
                  className="p-1 text-zinc-400 hover:text-zinc-600"
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>

            {totpSetupData.backup_codes && totpSetupData.backup_codes.length > 0 && (
              <div className="space-y-1">
                <span className="block text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                  {t('system.totp_backup_codes_title')}
                </span>
                <p className="text-[11px] text-zinc-500">
                  {t('system.totp_backup_codes_warning')}
                </p>
                <div className="grid grid-cols-2 gap-1.5 p-2 rounded-lg bg-zinc-100 dark:bg-zinc-800 font-mono text-[11px]">
                  {totpSetupData.backup_codes.map((code) => (
                    <div key={code} className="text-zinc-700 dark:text-zinc-300">
                      {code}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="pt-2">
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                {t('system.totp_confirm_code')}
              </label>
              <input
                type="text"
                maxLength={6}
                value={totpVerificationCode}
                onChange={(e) => setTotpVerificationCode(e.target.value.replace(/\D/g, ''))}
                placeholder="123456"
                className="w-full px-3 py-2 text-center text-lg font-mono tracking-widest rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
              />
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3">
              <button
                type="button"
                onClick={() => setTotpModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (totpVerificationCode.length === 6) {
                    enableTotpMutation.mutate(totpVerificationCode);
                  }
                }}
                disabled={totpVerificationCode.length !== 6 || enableTotpMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
              >
                {t('system.verify_and_enable')}
              </button>
            </div>
          </div>
        </div>
      )}

      {restoreModalOpen && restorePrepared && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4">
            <h2 className="text-lg font-bold text-rose-600 flex items-center space-x-2">
              <ShieldAlert className="h-5 w-5" />
              <span>{t('system.restore_modal_title')}</span>
            </h2>

            <p className="text-xs text-zinc-600 dark:text-zinc-400">
              {t('system.restore_warning')}
            </p>

            <div className="rounded-lg border border-gray-200 dark:border-zinc-800 bg-zinc-950 p-3 max-h-48 overflow-auto font-mono text-[11px] text-zinc-300">
              <pre>{restorePrepared.config_preview}</pre>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3">
              <button
                type="button"
                onClick={() => setRestoreModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() =>
                  confirmRestoreMutation.mutate(restorePrepared.confirmation_token)
                }
                disabled={confirmRestoreMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-rose-600 text-white hover:bg-rose-700 transition"
              >
                {t('system.confirm_restore_btn')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
