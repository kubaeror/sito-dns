import React, { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { notifications } from '@mantine/notifications';
import {
  Play,
  Save,
  Plus,
  Trash2,
  Activity,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';
import apiClient from '../api/client';
import type { UpstreamConfigDto, UpstreamTestItem } from '../api/types';

export const UpstreamsView: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const [servers, setServers] = useState<string[]>([]);
  const [bootstrap, setBootstrap] = useState<string[]>([]);
  const [strategy, setStrategy] = useState('failover');
  const [timeoutMs, setTimeoutMs] = useState(5000);
  const [probeDomain, setProbeDomain] = useState('example.com');
  const [poolSize, setPoolSize] = useState(4);
  const [newServerInput, setNewServerInput] = useState('');
  const [newBootstrapInput, setNewBootstrapInput] = useState('');
  const [testResults, setTestResults] = useState<UpstreamTestItem[] | null>(null);

  const { data: config, isLoading } = useQuery({
    queryKey: ['upstream-config'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/upstream');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  useEffect(() => {
    if (config) {
      setServers(config.servers || []);
      setBootstrap(config.bootstrap || []);
      setStrategy(config.strategy || 'failover');
      setTimeoutMs(config.timeout_ms || 5000);
      setProbeDomain(config.probe_domain || 'example.com');
      setPoolSize(config.pool_size || 4);
    }
  }, [config]);

  const saveMutation = useMutation({
    mutationFn: async () => {
      const payload: UpstreamConfigDto = {
        servers,
        bootstrap,
        strategy,
        timeout_ms: timeoutMs,
        probe_domain: probeDomain,
        pool_size: poolSize,
      };
      const res = await apiClient.PUT('/api/v1/upstream', {
        body: payload,
      });
      if (res.error || !res.data) throw res.error || new Error('Save failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: t('upstreams.upstreams_saved'),
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['upstream-config'] });
    },
  });

  const testMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/upstream/test', {
        body: {
          servers,
        },
      });
      if (res.error || !res.data) throw res.error || new Error('Test failed');
      return res.data;
    },
    onSuccess: (data) => {
      setTestResults(data.results || []);
    },
  });

  const handleAddServer = () => {
    if (newServerInput.trim() && !servers.includes(newServerInput.trim())) {
      setServers([...servers, newServerInput.trim()]);
      setNewServerInput('');
    }
  };

  const handleRemoveServer = (index: number) => {
    setServers(servers.filter((_, i) => i !== index));
  };

  const handleAddBootstrap = () => {
    if (newBootstrapInput.trim() && !bootstrap.includes(newBootstrapInput.trim())) {
      setBootstrap([...bootstrap, newBootstrapInput.trim()]);
      setNewBootstrapInput('');
    }
  };

  const handleRemoveBootstrap = (index: number) => {
    setBootstrap(bootstrap.filter((_, i) => i !== index));
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            {t('upstreams.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('upstreams.subtitle')}
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={() => testMutation.mutate()}
            disabled={testMutation.isPending || servers.length === 0}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200 hover:bg-gray-50 dark:hover:bg-zinc-700 transition"
          >
            <Play className={`h-3.5 w-3.5 text-emerald-500 ${testMutation.isPending ? 'animate-pulse' : ''}`} />
            <span>{testMutation.isPending ? t('common.testing') : t('upstreams.test_upstreams_btn')}</span>
          </button>

          <button
            type="button"
            onClick={() => saveMutation.mutate()}
            disabled={saveMutation.isPending || isLoading}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
          >
            <Save className="h-4 w-4" />
            <span>{t('upstreams.save_upstreams')}</span>
          </button>
        </div>
      </div>

      {testResults && testResults.length > 0 && (
        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-emerald-300 dark:border-emerald-800/60 shadow-xs space-y-3">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white flex items-center space-x-2">
            <Activity className="h-4 w-4 text-emerald-500" />
            <span>{t('upstreams.test_results_title')}</span>
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {testResults.map((res) => {
              const hasError = Boolean(res.error);
              return (
                <div
                  key={res.server}
                  className={`p-3 rounded-lg border flex flex-col justify-between ${
                    hasError
                      ? 'bg-rose-50 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/50'
                      : 'bg-emerald-50/40 dark:bg-emerald-950/20 border-emerald-200 dark:border-emerald-900/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-white truncate" title={res.server}>
                      {res.server}
                    </span>
                    {hasError ? (
                      <AlertTriangle className="h-4 w-4 text-rose-500 shrink-0" />
                    ) : (
                      <CheckCircle2 className="h-4 w-4 text-emerald-500 shrink-0" />
                    )}
                  </div>
                  <div className="mt-2 flex items-baseline justify-between text-xs">
                    <span className="text-zinc-500">Latency:</span>
                    <span className={`font-mono font-bold ${hasError ? 'text-rose-600' : 'text-emerald-600 dark:text-emerald-400'}`}>
                      {res.rtt_ms !== null ? `${res.rtt_ms} ms` : 'Failed'}
                    </span>
                  </div>
                  {res.error && (
                    <span className="text-[10px] text-rose-600 dark:text-rose-400 mt-1 truncate" title={res.error}>
                      {res.error}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
          <div>
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
              {t('upstreams.servers_list')}
            </h2>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
              Supports plain IP:port (1.1.1.1:53), DoT (tls://1.1.1.1), and DoH (https://cloudflare-dns.com/dns-query).
            </p>
          </div>

          <div className="space-y-2">
            {servers.map((srv, idx) => (
              <div
                key={srv}
                className="p-3 rounded-lg border border-gray-200 dark:border-zinc-800 flex items-center justify-between font-mono text-xs bg-gray-50/50 dark:bg-zinc-900/50"
              >
                <div className="flex items-center space-x-2">
                  <span className="text-zinc-600 dark:text-zinc-300 w-4">{idx + 1}.</span>
                  <span className="font-semibold text-zinc-900 dark:text-white">{srv}</span>
                </div>
                <button
                  type="button"
                  onClick={() => handleRemoveServer(idx)}
                  className="p-1 rounded text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50 transition"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}

            <div className="flex items-center space-x-2 pt-2">
              <input
                type="text"
                value={newServerInput}
                onChange={(e) => setNewServerInput(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleAddServer();
                }}
                placeholder="e.g. 9.9.9.9:53 or tls://dns.quad9.net"
                className="flex-1 px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
              />
              <button
                type="button"
                onClick={handleAddServer}
                className="inline-flex items-center space-x-1 px-3 py-1.5 text-xs font-semibold rounded-lg bg-zinc-800 dark:bg-zinc-700 text-white hover:bg-zinc-700"
              >
                <Plus className="h-3.5 w-3.5" />
                <span>{t('common.add')}</span>
              </button>
            </div>
          </div>

          <div className="pt-4 border-t border-gray-200 dark:border-zinc-800 space-y-2">
            <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">
              {t('upstreams.bootstrap_dns')}
            </h3>
            <p className="text-xs text-zinc-500">
              Direct IP addresses used to resolve hostnames for DoT / DoH resolvers before encryption connects.
            </p>
            <div className="space-y-2">
              {bootstrap.map((b, idx) => (
                <div
                  key={b}
                  className="p-2.5 rounded-lg border border-gray-200 dark:border-zinc-800 flex items-center justify-between font-mono text-xs bg-gray-50/50 dark:bg-zinc-900/50"
                >
                  <span className="text-zinc-800 dark:text-zinc-200">{b}</span>
                  <button
                    type="button"
                    onClick={() => handleRemoveBootstrap(idx)}
                    className="p-1 rounded text-zinc-400 hover:text-rose-600"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}

              <div className="flex items-center space-x-2 pt-1">
                <input
                  type="text"
                  value={newBootstrapInput}
                  onChange={(e) => setNewBootstrapInput(e.target.value)}
                  placeholder="e.g. 1.1.1.1"
                  className="flex-1 px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
                <button
                  type="button"
                  onClick={handleAddBootstrap}
                  className="inline-flex items-center space-x-1 px-3 py-1.5 text-xs font-semibold rounded-lg bg-zinc-800 dark:bg-zinc-700 text-white hover:bg-zinc-700"
                >
                  <Plus className="h-3.5 w-3.5" />
                  <span>{t('common.add')}</span>
                </button>
              </div>
            </div>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
            {t('upstreams.strategy_label')}
          </h2>

          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                Forwarding Mode
              </label>
              <select
                value={strategy}
                onChange={(e) => setStrategy(e.target.value)}
                className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-medium"
              >
                <option value="failover">{t('upstreams.strategy_failover')}</option>
                <option value="parallel">{t('upstreams.strategy_parallel')}</option>
                <option value="load_balance">{t('upstreams.strategy_load_balance')}</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                {t('upstreams.timeout_ms')}
              </label>
              <input
                type="number"
                min="500"
                max="30000"
                step="500"
                value={timeoutMs}
                onChange={(e) => setTimeoutMs(parseInt(e.target.value, 10) || 5000)}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                {t('upstreams.probe_domain')}
              </label>
              <input
                type="text"
                value={probeDomain}
                onChange={(e) => setProbeDomain(e.target.value)}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                {t('upstreams.pool_size')}
              </label>
              <input
                type="number"
                min="1"
                max="64"
                value={poolSize}
                onChange={(e) => setPoolSize(parseInt(e.target.value, 10) || 4)}
                className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
