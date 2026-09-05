import React, { useState, useEffect, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { notifications } from '@mantine/notifications';
import CodeMirror from '@uiw/react-codemirror';
import { oneDark } from '@codemirror/theme-one-dark';
import {
  Settings,
  FileText,
  Save,
  RotateCcw,
  RefreshCw,
  GitCompare,
  Sliders,
  Shield,
  Zap,
  Activity,
} from 'lucide-react';
import apiClient from '../api/client';
import { useTheme } from '../context/ThemeContext';

export const SettingsView: React.FC = () => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<'visual' | 'toml'>('visual');
  const [originalToml, setOriginalToml] = useState('');
  const [editedToml, setEditedToml] = useState('');
  const [diffModalOpen, setDiffModalOpen] = useState(false);

  // Form states for visual settings editor
  const [role, setRole] = useState('master');
  const [instanceName, setInstanceName] = useState('sito-main');
  const [logLevel, setLogLevel] = useState('info');
  const [dnsPort, setDnsPort] = useState(53);
  const [dotPort, setDotPort] = useState(853);
  const [dohPort, setDohPort] = useState(443);
  const [cacheEnabled, setCacheEnabled] = useState(true);
  const [cacheSizeMb, setCacheSizeMb] = useState(64);
  const [minTtl, setMinTtl] = useState(60);
  const [maxTtl, setMaxTtl] = useState(86400);
  const [prefetch, setPrefetch] = useState(false);
  const [rateLimit, setRateLimit] = useState(20);
  const [maxTcp, setMaxTcp] = useState(256);

  // Query: Get full Config
  const { data: configData } = useQuery({
    queryKey: ['server-config'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/config');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  useEffect(() => {
    if (configData?.config_toml) {
      setOriginalToml(configData.config_toml);
      setEditedToml(configData.config_toml);
      parseTomlToForm(configData.config_toml);
    }
  }, [configData]);

  // Parse simple fields out of TOML for visual editor
  const parseTomlToForm = (toml: string) => {
    const lines = toml.split('\n');
    lines.forEach((line) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('role =')) {
        const val = trimmed.split('=')[1]?.trim().replace(/"/g, '');
        if (val) setRole(val);
      } else if (trimmed.startsWith('instance_name =')) {
        const val = trimmed.split('=')[1]?.trim().replace(/"/g, '');
        if (val) setInstanceName(val);
      } else if (trimmed.startsWith('log_level =')) {
        const val = trimmed.split('=')[1]?.trim().replace(/"/g, '');
        if (val) setLogLevel(val);
      } else if (trimmed.startsWith('port =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setDnsPort(val);
      } else if (trimmed.startsWith('dot_port =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setDotPort(val);
      } else if (trimmed.startsWith('doh_port =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setDohPort(val);
      } else if (trimmed.startsWith('size_mb =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setCacheSizeMb(val);
      } else if (trimmed.startsWith('min_ttl =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setMinTtl(val);
      } else if (trimmed.startsWith('max_ttl =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setMaxTtl(val);
      } else if (trimmed.startsWith('prefetch =')) {
        setPrefetch(trimmed.includes('true'));
      } else if (trimmed.startsWith('rate_limit_per_ip =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setRateLimit(val);
      } else if (trimmed.startsWith('max_tcp_connections =')) {
        const val = parseInt(trimmed.split('=')[1]?.trim(), 10);
        if (!isNaN(val)) setMaxTcp(val);
      }
    });
  };

  const syncFormToToml = () => {
    let toml = editedToml;
    const replaceOrKeep = (key: string, newVal: string) => {
      const regex = new RegExp(`^(\\s*${key}\\s*=).*$`, 'm');
      if (regex.test(toml)) {
        toml = toml.replace(regex, `$1 ${newVal}`);
      }
    };

    replaceOrKeep('role', `"${role}"`);
    replaceOrKeep('instance_name', `"${instanceName}"`);
    replaceOrKeep('log_level', `"${logLevel}"`);
    replaceOrKeep('port', `${dnsPort}`);
    replaceOrKeep('dot_port', `${dotPort}`);
    replaceOrKeep('doh_port', `${dohPort}`);
    replaceOrKeep('size_mb', `${cacheSizeMb}`);
    replaceOrKeep('min_ttl', `${minTtl}`);
    replaceOrKeep('max_ttl', `${maxTtl}`);
    replaceOrKeep('prefetch', `${prefetch}`);
    replaceOrKeep('rate_limit_per_ip', `${rateLimit}`);
    replaceOrKeep('max_tcp_connections', `${maxTcp}`);

    setEditedToml(toml);
  };

  const saveMutation = useMutation({
    mutationFn: async (toml: string) => {
      const res = await apiClient.PUT('/api/v1/config', {
        body: { config_toml: toml },
      });
      if (res.error || !res.data) throw res.error || new Error('Save failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Configuration saved and hot-reloaded',
        color: 'teal',
      });
      setDiffModalOpen(false);
      setOriginalToml(editedToml);
      queryClient.invalidateQueries({ queryKey: ['server-config'] });
    },
  });

  const reloadMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/config/reload');
      if (res.error || !res.data) throw res.error || new Error('Reload failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: t('settings.reload_success'),
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['server-config'] });
    },
  });

  const diffLines = useMemo(() => {
    const orig = originalToml.split('\n');
    const edit = editedToml.split('\n');
    const diff: Array<{ type: 'same' | 'added' | 'removed'; text: string }> = [];

    const maxLen = Math.max(orig.length, edit.length);
    for (let i = 0; i < maxLen; i++) {
      const o = orig[i];
      const e = edit[i];
      if (o === e) {
        if (o !== undefined) diff.push({ type: 'same', text: o });
      } else {
        if (o !== undefined) diff.push({ type: 'removed', text: o });
        if (e !== undefined) diff.push({ type: 'added', text: e });
      }
    }
    return diff;
  }, [originalToml, editedToml]);

  const hasDiff = originalToml.trim() !== editedToml.trim();

  const handleOpenDiff = () => {
    if (activeTab === 'visual') {
      syncFormToToml();
    }
    setDiffModalOpen(true);
  };

  const handleRevert = () => {
    setEditedToml(originalToml);
    parseTomlToForm(originalToml);
    notifications.show({
      title: 'Reverted',
      message: 'Restored current running configuration',
      color: 'blue',
    });
  };

  const isDarkMode =
    theme === 'dark' ||
    (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            {t('settings.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('settings.subtitle')}
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={() => reloadMutation.mutate()}
            disabled={reloadMutation.isPending}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 hover:bg-gray-50 dark:hover:bg-zinc-700 transition"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${reloadMutation.isPending ? 'animate-spin' : ''}`} />
            <span>{t('settings.reload_disk_btn')}</span>
          </button>

          {hasDiff && (
            <button
              type="button"
              onClick={handleRevert}
              className="inline-flex items-center space-x-1 px-3 py-2 text-xs font-medium rounded-lg text-zinc-600 dark:text-zinc-400 hover:bg-gray-100 dark:hover:bg-zinc-800 transition"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>{t('settings.revert')}</span>
            </button>
          )}

          <button
            type="button"
            onClick={handleOpenDiff}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition shadow-xs"
          >
            <GitCompare className="h-4 w-4" />
            <span>{t('settings.diff_preview_title')}</span>
          </button>
        </div>
      </div>

      <div className="flex border-b border-gray-200 dark:border-zinc-800 space-x-6">
        <button
          type="button"
          onClick={() => setActiveTab('visual')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'visual'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <Sliders className="h-4 w-4" />
          <span>Visual Config Sections</span>
        </button>

        <button
          type="button"
          onClick={() => {
            if (activeTab === 'visual') syncFormToToml();
            setActiveTab('toml');
          }}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'toml'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <FileText className="h-4 w-4" />
          <span>{t('settings.tab_toml')}</span>
        </button>
      </div>

      {activeTab === 'visual' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
              <Settings className="h-4 w-4 text-emerald-500" />
              <span>{t('settings.tab_general')}</span>
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.server_role')}
                </label>
                <select
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-medium"
                >
                  <option value="master">master (Primary / Standalone)</option>
                  <option value="slave">slave (Replica, Read-Only)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.instance_name')}
                </label>
                <input
                  type="text"
                  value={instanceName}
                  onChange={(e) => setInstanceName(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.log_level')}
                </label>
                <select
                  value={logLevel}
                  onChange={(e) => setLogLevel(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                >
                  <option value="trace">trace</option>
                  <option value="debug">debug</option>
                  <option value="info">info</option>
                  <option value="warn">warn</option>
                  <option value="error">error</option>
                </select>
              </div>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
              <Shield className="h-4 w-4 text-emerald-500" />
              <span>{t('settings.tab_dns')}</span>
            </h2>

            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.dns_port')}
                </label>
                <input
                  type="number"
                  value={dnsPort}
                  onChange={(e) => setDnsPort(parseInt(e.target.value, 10) || 53)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.dot_port')}
                </label>
                <input
                  type="number"
                  value={dotPort}
                  onChange={(e) => setDotPort(parseInt(e.target.value, 10) || 853)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.doh_port')}
                </label>
                <input
                  type="number"
                  value={dohPort}
                  onChange={(e) => setDohPort(parseInt(e.target.value, 10) || 443)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                />
              </div>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
              <Zap className="h-4 w-4 text-emerald-500" />
              <span>{t('settings.tab_cache')}</span>
            </h2>

            <div className="space-y-3">
              <label className="flex items-center space-x-2 text-xs text-zinc-800 dark:text-zinc-200 cursor-pointer">
                <input
                  type="checkbox"
                  checked={cacheEnabled}
                  onChange={(e) => setCacheEnabled(e.target.checked)}
                  className="rounded border-gray-300 text-emerald-600 focus:ring-emerald-500"
                />
                <span>{t('settings.cache_enabled')}</span>
              </label>

              <div className="grid grid-cols-3 gap-3">
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('settings.cache_size_mb')}
                  </label>
                  <input
                    type="number"
                    value={cacheSizeMb}
                    onChange={(e) => setCacheSizeMb(parseInt(e.target.value, 10) || 64)}
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('settings.min_ttl')}
                  </label>
                  <input
                    type="number"
                    value={minTtl}
                    onChange={(e) => setMinTtl(parseInt(e.target.value, 10) || 60)}
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('settings.max_ttl')}
                  </label>
                  <input
                    type="number"
                    value={maxTtl}
                    onChange={(e) => setMaxTtl(parseInt(e.target.value, 10) || 86400)}
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                  />
                </div>
              </div>

              <label className="flex items-center space-x-2 text-xs text-zinc-800 dark:text-zinc-200 cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={prefetch}
                  onChange={(e) => setPrefetch(e.target.checked)}
                  className="rounded border-gray-300 text-emerald-600 focus:ring-emerald-500"
                />
                <span>{t('settings.prefetch')}</span>
              </label>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
              <Activity className="h-4 w-4 text-emerald-500" />
              <span>{t('settings.tab_rate_limit')}</span>
            </h2>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.rate_limit_per_ip')}
                </label>
                <input
                  type="number"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(parseInt(e.target.value, 10) || 0)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('settings.max_tcp_conn')}
                </label>
                <input
                  type="number"
                  value={maxTcp}
                  onChange={(e) => setMaxTcp(parseInt(e.target.value, 10) || 256)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
                />
              </div>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'toml' && (
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs p-5 space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Directly view and edit the raw <code className="font-mono">config.toml</code> document. Secrets are masked with <code className="font-mono">***</code>.
            </p>
          </div>

          <div className="border border-gray-200 dark:border-zinc-800 rounded-lg overflow-hidden font-mono text-xs">
            <CodeMirror
              value={editedToml}
              height="480px"
              theme={isDarkMode ? oneDark : undefined}
              onChange={(val) => setEditedToml(val)}
            />
          </div>
        </div>
      )}

      {diffModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-3xl rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4 max-h-[90vh] flex flex-col">
            <div className="flex items-center justify-between pb-2 border-b border-gray-200 dark:border-zinc-800">
              <h2 className="text-lg font-bold text-zinc-900 dark:text-white flex items-center space-x-2">
                <GitCompare className="h-5 w-5 text-emerald-500" />
                <span>{t('settings.diff_preview_title')}</span>
              </h2>
            </div>

            <p className="text-xs text-zinc-500">
              {hasDiff ? t('settings.diff_has_changes') : t('settings.diff_no_changes')}
            </p>

            <div className="flex-1 overflow-auto rounded-lg border border-gray-200 dark:border-zinc-800 bg-zinc-950 p-4 font-mono text-xs text-zinc-200 divide-y divide-zinc-900">
              {hasDiff ? (
                diffLines.map((line, idx) => {
                  if (line.type === 'added') {
                    return (
                      <div key={idx} className="bg-emerald-950/50 text-emerald-300 py-0.5 px-2">
                        + {line.text}
                      </div>
                    );
                  } else if (line.type === 'removed') {
                    return (
                      <div key={idx} className="bg-rose-950/50 text-rose-300 py-0.5 px-2">
                        - {line.text}
                      </div>
                    );
                  } else {
                    return (
                      <div key={idx} className="text-zinc-500 py-0.5 px-2 opacity-60">
                        &nbsp; {line.text}
                      </div>
                    );
                  }
                })
              ) : (
                <div className="text-center py-8 text-zinc-500">
                  No configuration differences found.
                </div>
              )}
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3 border-t border-gray-200 dark:border-zinc-800">
              <button
                type="button"
                onClick={() => setDiffModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() => saveMutation.mutate(editedToml)}
                disabled={!hasDiff || saveMutation.isPending}
                className="inline-flex items-center space-x-1.5 px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition disabled:opacity-50"
              >
                <Save className="h-4 w-4" />
                <span>{t('settings.save_and_reload')}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
