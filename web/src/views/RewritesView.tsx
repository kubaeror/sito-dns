import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { notifications } from '@mantine/notifications';
import {
  Globe,
  Plus,
  Trash2,
  Play,
  Search,
} from 'lucide-react';
import apiClient from '../api/client';
import type { RewriteDto, AddRewriteRequest } from '../api/types';

export const RewritesView: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  // Search & Modals
  const [searchTerm, setSearchTerm] = useState('');
  const [addModalOpen, setAddModalOpen] = useState(false);
  const [rewriteDomain, setRewriteDomain] = useState('');
  const [rewriteType, setRewriteType] = useState('A');
  const [rewriteAnswer, setRewriteAnswer] = useState('');
  const [exceptionClients, setExceptionClients] = useState('');

  // Local Resolution Test
  const [testDomain, setTestDomain] = useState('');
  const [testResult, setTestResult] = useState<{ matched: boolean; rule?: string; answer?: string } | null>(null);

  // Query: Rewrites
  const { data: rewrites, isLoading } = useQuery({
    queryKey: ['rewrites'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/rewrites');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Mutation: Add Rewrite
  const addMutation = useMutation({
    mutationFn: async () => {
      const payload: AddRewriteRequest = {
        domain: rewriteDomain.trim(),
        record_type: rewriteType,
        answer: rewriteAnswer.trim(),
        exception_clients: exceptionClients
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      };
      const res = await apiClient.POST('/api/v1/rewrites', {
        body: payload,
      });
      if (res.error || !res.data) throw res.error || new Error('Add failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'DNS rewrite record added',
        color: 'teal',
      });
      setAddModalOpen(false);
      setRewriteDomain('');
      setRewriteAnswer('');
      setExceptionClients('');
      queryClient.invalidateQueries({ queryKey: ['rewrites'] });
    },
  });

  // Mutation: Delete Rewrite
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      const res = await apiClient.DELETE('/api/v1/rewrites/{id}', {
        params: { path: { id } },
      });
      if (res.error || !res.data) throw res.error || new Error('Delete failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'DNS rewrite record deleted',
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['rewrites'] });
    },
  });

  // Test local resolution simulation
  const handleTestResolution = () => {
    if (!testDomain.trim() || !rewrites) return;
    const target = testDomain.trim().toLowerCase();

    let match: RewriteDto | undefined;
    for (const r of rewrites) {
      const pat = r.domain.toLowerCase();
      if (pat.startsWith('*.')) {
        const suffix = pat.slice(2);
        if (target.endsWith(suffix) || target === suffix) {
          match = r;
          break;
        }
      } else if (pat === target) {
        match = r;
        break;
      }
    }

    if (match) {
      setTestResult({
        matched: true,
        rule: match.domain,
        answer: `${match.record_type} -> ${match.answer}`,
      });
    } else {
      setTestResult({
        matched: false,
      });
    }
  };

  const filteredRewrites = (rewrites || []).filter((r) => {
    if (!searchTerm) return true;
    const term = searchTerm.toLowerCase();
    return (
      r.domain.toLowerCase().includes(term) ||
      r.answer.toLowerCase().includes(term) ||
      r.record_type.toLowerCase().includes(term)
    );
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            {t('rewrites.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('rewrites.subtitle')}
          </p>
        </div>

        <button
          type="button"
          onClick={() => setAddModalOpen(true)}
          className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
        >
          <Plus className="h-4 w-4" />
          <span>{t('rewrites.add_rewrite')}</span>
        </button>
      </div>

      <div className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="flex-1 relative">
          <Globe className="absolute left-3 top-2.5 h-4 w-4 text-zinc-400" />
          <input
            type="text"
            value={testDomain}
            onChange={(e) => setTestDomain(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') handleTestResolution();
            }}
            placeholder={t('rewrites.test_placeholder')}
            className="w-full pl-9 pr-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
          />
        </div>
        <button
          type="button"
          onClick={handleTestResolution}
          disabled={!testDomain.trim()}
          className="inline-flex items-center justify-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-zinc-800 dark:bg-zinc-700 text-white hover:bg-zinc-700 transition"
        >
          <Play className="h-3.5 w-3.5 text-emerald-400" />
          <span>{t('rewrites.resolve_btn')}</span>
        </button>

        {testResult && (
          <div className="sm:ml-2 flex items-center space-x-2 text-xs">
            {testResult.matched ? (
              <span className="px-2.5 py-1 rounded-md bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-mono font-medium">
                MATCH: {testResult.answer} (pattern: {testResult.rule})
              </span>
            ) : (
              <span className="px-2.5 py-1 rounded-md bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400">
                No rewrite matched (forwarded upstream)
              </span>
            )}
          </div>
        )}
      </div>

      <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs overflow-hidden">
        <div className="p-3 border-b border-gray-200 dark:border-zinc-800 flex items-center justify-between">
          <div className="relative w-64">
            <Search className="absolute left-2.5 top-2 h-3.5 w-3.5 text-zinc-400" />
            <input
              type="text"
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              placeholder="Search rewrites..."
              className="w-full pl-8 pr-3 py-1 text-xs rounded-md border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
            />
          </div>
          <span className="text-xs text-zinc-500 font-mono">
            {filteredRewrites.length} records
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50/70 dark:bg-zinc-900/70 font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">{t('rewrites.domain')}</th>
                <th className="py-3 px-4">{t('rewrites.record_type')}</th>
                <th className="py-3 px-4">{t('rewrites.answer')}</th>
                <th className="py-3 px-4">{t('rewrites.exception_clients')}</th>
                <th className="py-3 px-4 text-right">{t('common.actions')}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
              {isLoading ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-zinc-400">
                    {t('common.loading')}
                  </td>
                </tr>
              ) : filteredRewrites.length > 0 ? (
                filteredRewrites.map((record) => (
                  <tr key={record.id} className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/40">
                    <td className="py-3 px-4 font-mono font-semibold text-zinc-900 dark:text-white">
                      {record.domain}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                        {record.record_type}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-mono text-emerald-600 dark:text-emerald-400 font-medium">
                      {record.answer}
                    </td>
                    <td className="py-3 px-4 text-zinc-500 font-mono text-[11px]">
                      {record.exception_clients?.join(', ') || '—'}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        type="button"
                        onClick={() => {
                          if (window.confirm(t('rewrites.delete_confirm', { domain: record.domain }))) {
                            deleteMutation.mutate(record.id);
                          }
                        }}
                        className="p-1 rounded text-zinc-400 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50 transition"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-zinc-400">
                    {t('rewrites.no_rewrites')}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {addModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4">
            <h2 className="text-lg font-bold text-zinc-900 dark:text-white">
              {t('rewrites.add_rewrite')}
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('rewrites.domain')}
                </label>
                <input
                  type="text"
                  value={rewriteDomain}
                  onChange={(e) => setRewriteDomain(e.target.value)}
                  placeholder="e.g. router.lan or *.internal.net"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('rewrites.record_type')}
                </label>
                <select
                  value={rewriteType}
                  onChange={(e) => setRewriteType(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                >
                  <option value="A">A (IPv4)</option>
                  <option value="AAAA">AAAA (IPv6)</option>
                  <option value="CNAME">CNAME (Alias)</option>
                  <option value="PTR">PTR (Reverse DNS)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('rewrites.answer')}
                </label>
                <input
                  type="text"
                  value={rewriteAnswer}
                  onChange={(e) => setRewriteAnswer(e.target.value)}
                  placeholder="e.g. 192.168.1.1 or target.server.com"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('rewrites.exception_clients')}
                </label>
                <input
                  type="text"
                  value={exceptionClients}
                  onChange={(e) => setExceptionClients(e.target.value)}
                  placeholder="IPs that bypass this rewrite"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3">
              <button
                type="button"
                onClick={() => setAddModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (rewriteDomain.trim() && rewriteAnswer.trim()) {
                    addMutation.mutate();
                  }
                }}
                disabled={!rewriteDomain.trim() || !rewriteAnswer.trim() || addMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
              >
                {t('common.add')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
