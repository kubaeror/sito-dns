import React, { useState, useEffect, useRef, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useVirtualizer } from '@tanstack/react-virtual';
import { useTranslation } from 'react-i18next';
import { notifications } from '@mantine/notifications';
import {
  Play,
  Pause,
  Trash2,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  ShieldBan,
  ShieldCheck,
  Radio,
  Check,
} from 'lucide-react';
import apiClient from '../api/client';
import { useAuthStore } from '../stores/authStore';
import type { QueryLogEntry } from '../api/types';

const QTYPE_NAMES: Record<number, string> = {
  1: 'A',
  28: 'AAAA',
  5: 'CNAME',
  65: 'HTTPS',
  16: 'TXT',
  12: 'PTR',
  15: 'MX',
  2: 'NS',
  6: 'SOA',
  257: 'CAA',
  48: 'DNSKEY',
  43: 'DS',
};

export const QueryLogView: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const token = useAuthStore((s) => s.token);

  // Filter states
  const [domainFilter, setDomainFilter] = useState('');
  const [clientFilter, setClientFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [qtypeFilter, setQtypeFilter] = useState('all');

  // Live streaming states
  const [isLive, setIsLive] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [expandedId, setExpandedId] = useState<number | string | null>(null);
  const [streamEntries, setStreamEntries] = useState<QueryLogEntry[]>([]);

  // Initial queries fetch
  const { data: initialPage, refetch: refetchQueryLog } = useQuery({
    queryKey: ['querylog', domainFilter, clientFilter, statusFilter, qtypeFilter],
    queryFn: async () => {
      const qtypeNum = qtypeFilter !== 'all' ? parseInt(qtypeFilter, 10) : undefined;
      const statusParam = statusFilter !== 'all' ? statusFilter : undefined;
      const res = await apiClient.GET('/api/v1/querylog', {
        params: {
          query: {
            domain: domainFilter || undefined,
            client: clientFilter || undefined,
            status: statusParam,
            qtype: isNaN(qtypeNum!) ? undefined : qtypeNum,
            limit: 200,
          },
        },
      });
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Sync initial entries
  useEffect(() => {
    if (initialPage?.entries) {
      setStreamEntries(initialPage.entries);
    }
  }, [initialPage]);

  // WebSocket Live Tail
  useEffect(() => {
    if (!isLive) return;

    let socket: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout> | null = null;
    let isCancelled = false;

    const connect = () => {
      if (isCancelled) return;
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/api/v1/querylog/stream${
        token ? `?token=${encodeURIComponent(token)}` : ''
      }`;

      try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
          if (!isCancelled) setWsConnected(true);
        };

        socket.onmessage = (event) => {
          if (isCancelled) return;
          try {
            const entry: QueryLogEntry = JSON.parse(event.data);
            setStreamEntries((prev) => [entry, ...prev.slice(0, 4999)]);
          } catch {
            // ignore non-json messages (pings)
          }
        };

        socket.onclose = () => {
          if (!isCancelled) {
            setWsConnected(false);
            reconnectTimeout = setTimeout(connect, 3000);
          }
        };

        socket.onerror = () => {
          if (socket) socket.close();
        };
      } catch {
        reconnectTimeout = setTimeout(connect, 3000);
      }
    };

    connect();

    return () => {
      isCancelled = true;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (socket) socket.close();
      setWsConnected(false);
    };
  }, [isLive, token]);

  // Filter entries in memory for instant responsiveness
  const filteredEntries = useMemo(() => {
    return streamEntries.filter((e) => {
      if (domainFilter && !e.qname.toLowerCase().includes(domainFilter.toLowerCase())) {
        return false;
      }
      if (clientFilter) {
        const matchesIp = e.client_ip.toLowerCase().includes(clientFilter.toLowerCase());
        const matchesName = e.client_name?.toLowerCase().includes(clientFilter.toLowerCase());
        if (!matchesIp && !matchesName) return false;
      }
      if (statusFilter !== 'all') {
        if (statusFilter === 'allowed' && e.verdict !== 'allowed') return false;
        if (statusFilter === 'blocked' && e.verdict !== 'blocked') return false;
        if (statusFilter === 'whitelisted' && e.verdict !== 'whitelisted') return false;
        if (statusFilter === 'rewritten' && e.verdict !== 'rewritten') return false;
      }
      if (qtypeFilter !== 'all' && e.qtype !== parseInt(qtypeFilter, 10)) {
        return false;
      }
      return true;
    });
  }, [streamEntries, domainFilter, clientFilter, statusFilter, qtypeFilter]);

  // Clear query log mutation
  const clearMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.DELETE('/api/v1/querylog');
      if (res.error || !res.data) throw res.error || new Error('Delete failed');
      return res.data;
    },
    onSuccess: () => {
      setStreamEntries([]);
      notifications.show({
        title: t('common.success'),
        message: 'Query log cleared',
        color: 'teal',
      });
      refetchQueryLog();
    },
  });

  // Add rule mutation (block or allow)
  const addRuleMutation = useMutation({
    mutationFn: async ({ rule }: { rule: string }) => {
      const currentRes = await apiClient.GET('/api/v1/filtering/rules');
      const existingRules = currentRes.data?.rules || [];
      if (!existingRules.includes(rule)) {
        const updated = [...existingRules, rule];
        const putRes = await apiClient.PUT('/api/v1/filtering/rules', {
          body: { rules: updated },
        });
        if (putRes.error) throw putRes.error;
      }
      return rule;
    },
    onSuccess: (rule) => {
      notifications.show({
        title: t('querylog.rule_added'),
        message: rule,
        icon: <Check className="h-4 w-4" />,
        color: 'emerald',
      });
      queryClient.invalidateQueries({ queryKey: ['filtering-rules'] });
    },
  });

  // Virtualizer setup
  const parentRef = useRef<HTMLDivElement>(null);
  const rowVirtualizer = useVirtualizer({
    count: filteredEntries.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => {
      const entry = filteredEntries[index];
      const rowId = entry?.id ?? `${entry?.ts}-${index}`;
      return expandedId === rowId ? 180 : 44;
    },
    overscan: 10,
  });

  const handleToggleExpand = (rowId: number | string) => {
    setExpandedId((prev) => (prev === rowId ? null : rowId));
    rowVirtualizer.measure();
  };

  const handleBlockDomain = (domain: string, e: React.MouseEvent) => {
    e.stopPropagation();
    addRuleMutation.mutate({ rule: `||${domain}^` });
  };

  const handleAllowDomain = (domain: string, e: React.MouseEvent) => {
    e.stopPropagation();
    addRuleMutation.mutate({ rule: `@@||${domain}^` });
  };

  const formatTimestamp = (ts: number) => {
    const d = new Date(ts);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  };

  const getVerdictBadge = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'allowed':
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-emerald-100 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300">
            {t('querylog.verdict_allowed')}
          </span>
        );
      case 'blocked':
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-rose-100 dark:bg-rose-950/70 text-rose-800 dark:text-rose-300">
            {t('querylog.verdict_blocked')}
          </span>
        );
      case 'whitelisted':
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-blue-100 dark:bg-blue-950/70 text-blue-800 dark:text-blue-300">
            {t('querylog.verdict_whitelisted')}
          </span>
        );
      case 'rewritten':
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-purple-100 dark:bg-purple-950/70 text-purple-800 dark:text-purple-300">
            {t('querylog.verdict_rewritten')}
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 text-[11px] font-semibold rounded-md bg-zinc-100 dark:bg-zinc-800 text-zinc-800 dark:text-zinc-200">
            {verdict}
          </span>
        );
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            {t('querylog.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('querylog.subtitle')}
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            type="button"
            onClick={() => setIsLive(!isLive)}
            className={`inline-flex items-center space-x-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg border transition ${
              isLive
                ? 'bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-300 border-zinc-300 dark:border-zinc-700'
            }`}
          >
            {isLive ? (
              <>
                <Radio className={`h-3.5 w-3.5 text-emerald-500 ${wsConnected ? 'animate-pulse' : ''}`} />
                <span>{t('querylog.live_tail_active')}</span>
                <Pause className="h-3 w-3 ml-1 text-zinc-400" />
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 text-zinc-500" />
                <span>{t('querylog.live_tail_paused')}</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => {
              if (window.confirm(t('querylog.clear_confirm'))) {
                clearMutation.mutate();
              }
            }}
            disabled={clearMutation.isPending}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-red-200 dark:border-red-900/50 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30 transition"
          >
            <Trash2 className="h-3.5 w-3.5" />
            <span>{t('querylog.clear_log')}</span>
          </button>
        </div>
      </div>

      <div className="p-3.5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-3 top-2.5 h-4 w-4 text-zinc-400" />
          <input
            type="text"
            value={domainFilter}
            onChange={(e) => setDomainFilter(e.target.value)}
            placeholder={t('querylog.search_placeholder')}
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
          />
        </div>

        <div className="min-w-[160px]">
          <input
            type="text"
            value={clientFilter}
            onChange={(e) => setClientFilter(e.target.value)}
            placeholder={t('querylog.client_filter')}
            className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
          />
        </div>

        <div className="flex items-center space-x-1">
          <Filter className="h-3.5 w-3.5 text-zinc-400" />
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
          >
            <option value="all">{t('querylog.all_statuses')}</option>
            <option value="allowed">{t('querylog.verdict_allowed')}</option>
            <option value="blocked">{t('querylog.verdict_blocked')}</option>
            <option value="whitelisted">{t('querylog.verdict_whitelisted')}</option>
            <option value="rewritten">{t('querylog.verdict_rewritten')}</option>
          </select>
        </div>

        <select
          value={qtypeFilter}
          onChange={(e) => setQtypeFilter(e.target.value)}
          className="px-2.5 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white focus:outline-none focus:ring-1 focus:ring-emerald-500"
        >
          <option value="all">{t('querylog.all_qtypes')}</option>
          <option value="1">A (1)</option>
          <option value="28">AAAA (28)</option>
          <option value="5">CNAME (5)</option>
          <option value="65">HTTPS (65)</option>
          <option value="16">TXT (16)</option>
          <option value="12">PTR (12)</option>
          <option value="15">MX (15)</option>
          <option value="2">NS (2)</option>
        </select>

        <span className="text-xs text-zinc-500 dark:text-zinc-400 ml-auto font-mono">
          {filteredEntries.length.toLocaleString()} queries
        </span>
      </div>

      <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs overflow-hidden">
        <div className="grid grid-cols-12 gap-2 px-4 py-2.5 border-b border-gray-200 dark:border-zinc-800 text-[11px] font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider bg-gray-50/70 dark:bg-zinc-900/70">
          <div className="col-span-2">{t('querylog.col_time')}</div>
          <div className="col-span-2">{t('querylog.col_client')}</div>
          <div className="col-span-4">{t('querylog.col_domain')}</div>
          <div className="col-span-1">{t('querylog.col_type')}</div>
          <div className="col-span-1">{t('querylog.col_verdict')}</div>
          <div className="col-span-2 text-right">{t('querylog.col_actions')}</div>
        </div>

        <div
          ref={parentRef}
          className="h-[560px] overflow-auto divide-y divide-gray-100 dark:divide-zinc-800 font-mono text-xs"
        >
          {filteredEntries.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center p-8 text-center text-zinc-400">
              <p>{t('querylog.no_logs')}</p>
            </div>
          ) : (
            <div
              style={{
                height: `${rowVirtualizer.getTotalSize()}px`,
                width: '100%',
                position: 'relative',
              }}
            >
              {rowVirtualizer.getVirtualItems().map((virtualRow) => {
                const item = filteredEntries[virtualRow.index];
                const rowId = item.id ?? `${item.ts}-${virtualRow.index}`;
                const isExpanded = expandedId === rowId;
                const elapsedMs = item.elapsed_us ? (item.elapsed_us / 1000).toFixed(1) : null;
                const qtypeName = QTYPE_NAMES[item.qtype] || `${item.qtype}`;

                return (
                  <div
                    key={virtualRow.key}
                    style={{
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      width: '100%',
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                    className={`transition-colors cursor-pointer ${
                      isExpanded
                        ? 'bg-emerald-50/50 dark:bg-emerald-950/20'
                        : 'hover:bg-gray-50/80 dark:hover:bg-zinc-800/40'
                    }`}
                    onClick={() => handleToggleExpand(rowId)}
                  >
                    <div className="grid grid-cols-12 gap-2 px-4 py-2.5 items-center">
                      <div className="col-span-2 flex items-center space-x-1.5 text-zinc-500 dark:text-zinc-400">
                        {isExpanded ? (
                          <ChevronDown className="h-3.5 w-3.5 shrink-0 text-emerald-500" />
                        ) : (
                          <ChevronRight className="h-3.5 w-3.5 shrink-0 text-zinc-400" />
                        )}
                        <span className="truncate">{formatTimestamp(item.ts)}</span>
                      </div>

                      <div className="col-span-2 truncate text-zinc-700 dark:text-zinc-300" title={item.client_name || item.client_ip}>
                        {item.client_name || item.client_ip}
                      </div>

                      <div className="col-span-4 font-semibold text-zinc-900 dark:text-white truncate" title={item.qname}>
                        {item.qname}
                      </div>

                      <div className="col-span-1 text-zinc-500 dark:text-zinc-400">
                        <span className="px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 text-[10px]">
                          {qtypeName}
                        </span>
                      </div>

                      <div className="col-span-1">
                        {getVerdictBadge(item.verdict)}
                      </div>

                      <div className="col-span-2 flex items-center justify-end space-x-2">
                        {item.verdict !== 'blocked' ? (
                          <button
                            type="button"
                            onClick={(e) => handleBlockDomain(item.qname, e)}
                            className="p-1 rounded text-rose-500 hover:bg-rose-50 dark:hover:bg-rose-950/50"
                            title={t('querylog.block_domain')}
                          >
                            <ShieldBan className="h-4 w-4" />
                          </button>
                        ) : (
                          <button
                            type="button"
                            onClick={(e) => handleAllowDomain(item.qname, e)}
                            className="p-1 rounded text-emerald-500 hover:bg-emerald-50 dark:hover:bg-emerald-950/50"
                            title={t('querylog.allow_domain')}
                          >
                            <ShieldCheck className="h-4 w-4" />
                          </button>
                        )}
                      </div>
                    </div>

                    {isExpanded && (
                      <div className="px-6 py-3 bg-zinc-50 dark:bg-zinc-950 border-t border-b border-gray-200 dark:border-zinc-800 font-sans text-xs grid grid-cols-1 sm:grid-cols-3 gap-3">
                        <div>
                          <span className="text-zinc-400 block text-[11px]">{t('querylog.rule_matched')}</span>
                          <span className="font-mono text-zinc-800 dark:text-zinc-200 font-medium">
                            {item.rule || '—'}
                          </span>
                          {item.list_source && (
                            <span className="text-[10px] text-zinc-400 block">
                              Source: {item.list_source}
                            </span>
                          )}
                        </div>

                        <div>
                          <span className="text-zinc-400 block text-[11px]">{t('querylog.upstream_server')}</span>
                          <span className="font-mono text-zinc-800 dark:text-zinc-200">
                            {item.upstream || 'Cached / Blocked locally'}
                          </span>
                          {elapsedMs && (
                            <span className="text-[10px] text-zinc-400 block">
                              Duration: {elapsedMs} ms ({item.elapsed_us} µs)
                            </span>
                          )}
                        </div>

                        <div>
                          <span className="text-zinc-400 block text-[11px]">{t('querylog.dnssec_status')}</span>
                          <span className="font-medium">
                            {item.dnssec === 'secure' ? (
                              <span className="text-emerald-600 dark:text-emerald-400">{t('querylog.dnssec_secure')}</span>
                            ) : item.dnssec === 'bogus' ? (
                              <span className="text-rose-600 dark:text-rose-400">{t('querylog.dnssec_bogus')}</span>
                            ) : (
                              <span className="text-zinc-500">{t('querylog.dnssec_none')}</span>
                            )}
                          </span>
                          <span className="text-[10px] text-zinc-400 block font-mono">
                            Proto: {item.proto?.toUpperCase()} | RCode: {item.rcode ?? 0}
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
