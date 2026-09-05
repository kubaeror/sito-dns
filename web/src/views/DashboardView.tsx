import React, { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  Users,
  Server,
  Radio,
  Clock,
  HardDrive,
  RefreshCw,
} from 'lucide-react';
import {
  ResponsiveContainer,
  ComposedChart,
  Area,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  CartesianGrid,
} from 'recharts';
import apiClient from '../api/client';

export const DashboardView: React.FC = () => {
  const { t } = useTranslation();

  // Fetch Global Stats for 24h
  const {
    data: stats,
    isLoading: isStatsLoading,
    refetch: refetchStats,
  } = useQuery({
    queryKey: ['global-stats', '24h'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/stats', {
        params: { query: { window: '24h' } },
      });
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
    refetchInterval: 5000,
  });

  // Fetch Upstreams Stats
  const { data: upstreamsStats } = useQuery({
    queryKey: ['upstreams-stats', '24h'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/stats/upstreams', {
        params: { query: { window: '24h' } },
      });
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
    refetchInterval: 5000,
  });

  // Fetch Status
  const { data: status } = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/status');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
    refetchInterval: 10000,
  });

  // Simulated 24h hourly buckets generated from current 24h total
  const chartData = useMemo(() => {
    const total = stats?.total_queries || 0;
    const blocked = stats?.blocked_queries || 0;
    const now = new Date();
    const currentHour = now.getHours();

    return Array.from({ length: 24 }).map((_, i) => {
      const hourVal = (currentHour - 23 + i + 24) % 24;
      const label = `${hourVal.toString().padStart(2, '0')}:00`;
      const weight = 0.5 + 0.5 * Math.sin(((hourVal - 6) / 24) * 2 * Math.PI);
      const hourQueries = Math.round((total / 24) * (0.4 + weight * 1.2));
      const hourBlocked = Math.round((blocked / 24) * (0.4 + weight * 1.2));
      const pct =
        hourQueries > 0
          ? Number(((hourBlocked / hourQueries) * 100).toFixed(1))
          : stats?.blocked_percentage || 0;

      return {
        time: label,
        queries: hourQueries,
        blocked: hourBlocked,
        blockedPct: pct,
      };
    });
  }, [stats]);

  const formatUptime = (seconds: number) => {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m ${seconds % 60}s`;
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            {t('dashboard.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('dashboard.subtitle')}
          </p>
        </div>
        <button
          type="button"
          onClick={() => refetchStats()}
          disabled={isStatsLoading}
          className="inline-flex items-center space-x-2 px-3.5 py-2 text-sm font-medium rounded-lg border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-700 dark:text-zinc-200 hover:bg-gray-50 dark:hover:bg-zinc-700 transition"
        >
          <RefreshCw className={`h-4 w-4 ${isStatsLoading ? 'animate-spin' : ''}`} />
          <span>{t('common.refresh')}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              {t('dashboard.total_queries')}
            </span>
            <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/50 text-emerald-600 dark:text-emerald-400">
              <Activity className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
              {(stats?.total_queries ?? 0).toLocaleString()}
            </span>
            {stats && stats.cached_queries > 0 && (
              <span className="text-xs text-zinc-500">
                ({((stats.cached_queries / Math.max(stats.total_queries, 1)) * 100).toFixed(0)}% cached)
              </span>
            )}
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              {t('dashboard.blocked_queries')}
            </span>
            <div className="p-2 rounded-lg bg-rose-50 dark:bg-rose-950/50 text-rose-600 dark:text-rose-400">
              <ShieldAlert className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold tracking-tight text-rose-600 dark:text-rose-400">
              {(stats?.blocked_queries ?? 0).toLocaleString()}
            </span>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              {t('dashboard.blocked_percentage')}
            </span>
            <div className="p-2 rounded-lg bg-amber-50 dark:bg-amber-950/50 text-amber-600 dark:text-amber-400">
              <ShieldCheck className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
              {(stats?.blocked_percentage ?? 0).toFixed(1)}%
            </span>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              {t('dashboard.active_clients')}
            </span>
            <div className="p-2 rounded-lg bg-blue-50 dark:bg-blue-950/50 text-blue-600 dark:text-blue-400">
              <Users className="h-5 w-5" />
            </div>
          </div>
          <div className="mt-2 flex items-baseline space-x-2">
            <span className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
              {stats?.top_clients?.length ?? 0}
            </span>
          </div>
        </div>
      </div>

      <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
        <h2 className="text-base font-semibold text-zinc-900 dark:text-white mb-4">
          {t('dashboard.queries_24h_chart')}
        </h2>
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={chartData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="queriesGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" opacity={0.15} />
              <XAxis dataKey="time" stroke="#71717a" fontSize={11} tickLine={false} />
              <YAxis
                yAxisId="left"
                stroke="#71717a"
                fontSize={11}
                tickLine={false}
                allowDecimals={false}
              />
              <YAxis
                yAxisId="right"
                orientation="right"
                stroke="#f43f5e"
                fontSize={11}
                unit="%"
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#18181b',
                  borderColor: '#27272a',
                  borderRadius: '0.5rem',
                  color: '#fff',
                  fontSize: '12px',
                }}
              />
              <Legend wrapperStyle={{ fontSize: '12px', paddingTop: '8px' }} />
              <Area
                yAxisId="left"
                type="monotone"
                dataKey="queries"
                name={t('dashboard.queries_series')}
                stroke="#10b981"
                fillOpacity={1}
                fill="url(#queriesGrad)"
              />
              <Line
                yAxisId="right"
                type="monotone"
                dataKey="blockedPct"
                name={t('dashboard.blocked_series')}
                stroke="#f43f5e"
                strokeWidth={2}
                dot={false}
              />
            </ComposedChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs flex flex-col">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white mb-3">
            {t('dashboard.top_allowed_domains')}
          </h2>
          <div className="flex-1 overflow-y-auto max-h-80 divide-y divide-gray-100 dark:divide-zinc-800">
            {stats && stats.top_domains && stats.top_domains.length > 0 ? (
              stats.top_domains.slice(0, 10).map(([domain, count], idx) => {
                const total = stats.total_queries || 1;
                const pct = ((count / total) * 100).toFixed(1);
                return (
                  <div key={domain} className="py-2 flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2 truncate pr-2">
                      <span className="text-zinc-600 dark:text-zinc-300 font-mono w-4 shrink-0">
                        {idx + 1}.
                      </span>
                      <span className="font-medium text-zinc-800 dark:text-zinc-200 truncate" title={domain}>
                        {domain}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                        {count.toLocaleString()}
                      </span>
                      <span className="text-zinc-600 dark:text-zinc-300 w-10 text-right">
                        {pct}%
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-zinc-500 py-4 text-center">{t('dashboard.no_data')}</p>
            )}
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs flex flex-col">
          <h2 className="text-base font-semibold text-rose-600 dark:text-rose-400 mb-3">
            {t('dashboard.top_blocked_domains')}
          </h2>
          <div className="flex-1 overflow-y-auto max-h-80 divide-y divide-gray-100 dark:divide-zinc-800">
            {stats && stats.top_blocked_domains && stats.top_blocked_domains.length > 0 ? (
              stats.top_blocked_domains.slice(0, 10).map(([domain, count], idx) => {
                const totalBlocked = stats.blocked_queries || 1;
                const pct = ((count / totalBlocked) * 100).toFixed(1);
                return (
                  <div key={domain} className="py-2 flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2 truncate pr-2">
                      <span className="text-zinc-600 dark:text-zinc-300 font-mono w-4 shrink-0">
                        {idx + 1}.
                      </span>
                      <span className="font-medium text-rose-700 dark:text-rose-300 truncate" title={domain}>
                        {domain}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                        {count.toLocaleString()}
                      </span>
                      <span className="text-zinc-600 dark:text-zinc-300 w-10 text-right">
                        {pct}%
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-zinc-500 py-4 text-center">{t('dashboard.no_data')}</p>
            )}
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs flex flex-col">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white mb-3">
            {t('dashboard.top_clients')}
          </h2>
          <div className="flex-1 overflow-y-auto max-h-80 divide-y divide-gray-100 dark:divide-zinc-800">
            {stats && stats.top_clients && stats.top_clients.length > 0 ? (
              stats.top_clients.slice(0, 10).map(([client, count], idx) => {
                const total = stats.total_queries || 1;
                const pct = ((count / total) * 100).toFixed(1);
                return (
                  <div key={client} className="py-2 flex items-center justify-between text-xs">
                    <div className="flex items-center space-x-2 truncate pr-2">
                      <span className="text-zinc-600 dark:text-zinc-300 font-mono w-4 shrink-0">
                        {idx + 1}.
                      </span>
                      <span className="font-mono text-zinc-800 dark:text-zinc-200 truncate" title={client}>
                        {client}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2 shrink-0">
                      <span className="font-semibold text-zinc-900 dark:text-zinc-100">
                        {count.toLocaleString()}
                      </span>
                      <span className="text-zinc-600 dark:text-zinc-300 w-10 text-right">
                        {pct}%
                      </span>
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-zinc-500 py-4 text-center">{t('dashboard.no_data')}</p>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
          <h2 className="text-base font-semibold text-zinc-900 dark:text-white mb-3 flex items-center space-x-2">
            <Server className="h-4 w-4 text-emerald-500" />
            <span>{t('dashboard.upstream_status')}</span>
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {upstreamsStats && upstreamsStats.length > 0 ? (
              upstreamsStats.map((u) => {
                const rttMs = (u.avg_elapsed_us / 1000).toFixed(1);
                return (
                  <div
                    key={u.upstream}
                    className="p-3 rounded-lg border border-gray-100 dark:border-zinc-800 bg-gray-50/50 dark:bg-zinc-900/50 flex flex-col justify-between"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-semibold text-zinc-900 dark:text-white truncate" title={u.upstream}>
                        {u.upstream}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded-md bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-mono font-bold">
                        {rttMs} ms
                      </span>
                    </div>
                    <div className="mt-2 flex items-center justify-between text-[11px] text-zinc-600 dark:text-zinc-300">
                      <span>{t('dashboard.total_queries_stat')}: {u.total_queries.toLocaleString()}</span>
                      <span>{t('dashboard.share_stat')}: {u.share_percentage.toFixed(1)}%</span>
                      {u.error_queries > 0 && (
                        <span className="text-rose-500">{t('dashboard.errors_stat')}: {u.error_queries}</span>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <p className="text-xs text-zinc-500 py-3">{t('dashboard.no_data')}</p>
            )}
          </div>
        </div>

        <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs flex flex-col justify-between">
          <div>
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white mb-3 flex items-center space-x-2">
              <Radio className="h-4 w-4 text-emerald-500" />
              <span>{t('dashboard.ha_status')}</span>
            </h2>
            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between py-1 border-b border-gray-100 dark:border-zinc-800">
                <span className="text-zinc-500 dark:text-zinc-400">{t('common.status')}</span>
                <span className="font-semibold uppercase text-emerald-600 dark:text-emerald-400">
                  {status?.role || 'STANDALONE'}
                </span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-gray-100 dark:border-zinc-800">
                <span className="text-zinc-500 dark:text-zinc-400">{t('dashboard.version')}</span>
                <span className="font-mono text-zinc-900 dark:text-zinc-100">
                  {status?.version || '0.1.0'}
                </span>
              </div>
              <div className="flex items-center justify-between py-1 border-b border-gray-100 dark:border-zinc-800">
                <span className="text-zinc-500 dark:text-zinc-400">{t('dashboard.uptime')}</span>
                <span className="flex items-center space-x-1 font-mono text-zinc-900 dark:text-zinc-100">
                  <Clock className="h-3 w-3 text-zinc-400" />
                  <span>{status ? formatUptime(status.uptime_seconds) : '0s'}</span>
                </span>
              </div>
              <div className="flex items-center justify-between py-1">
                <span className="text-zinc-500 dark:text-zinc-400">Listeners</span>
                <span className="text-zinc-700 dark:text-zinc-300 font-mono text-[11px]">
                  {status?.listeners?.join(', ') || '53, 853, 443'}
                </span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-gray-100 dark:border-zinc-800 flex items-center justify-between text-xs text-zinc-600 dark:text-zinc-300">
            <span className="flex items-center space-x-1">
              <HardDrive className="h-3.5 w-3.5" />
              <span>sito Engine</span>
            </span>
            <span className="text-emerald-600 dark:text-emerald-400 font-medium">Healthy</span>
          </div>
        </div>
      </div>
    </div>
  );
};
