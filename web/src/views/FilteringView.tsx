import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { notifications } from '@mantine/notifications';
import CodeMirror from '@uiw/react-codemirror';
import { oneDark } from '@codemirror/theme-one-dark';
import {
  ListFilter,
  FileCode,
  Lock,
  Baby,
  Plus,
  RefreshCw,
  Trash2,
  Play,
  Save,
  ExternalLink,
} from 'lucide-react';
import apiClient from '../api/client';
import { useTheme } from '../context/ThemeContext';
import type {
  FilterListDto,
  FilterCheckResponse,
  ClientGroupDto,
} from '../api/types';

const POPULAR_SERVICES = [
  { id: 'tiktok', name: 'TikTok', icon: '🎵', desc: 'Short-form video app and CDNs' },
  { id: 'youtube', name: 'YouTube', icon: '▶️', desc: 'Video streaming and comments' },
  { id: 'facebook', name: 'Facebook & Meta', icon: '👤', desc: 'Social platform and telemetry' },
  { id: 'instagram', name: 'Instagram', icon: '📷', desc: 'Photo and reels sharing' },
  { id: 'steam', name: 'Steam', icon: '🎮', desc: 'Valve gaming platform store' },
  { id: 'discord', name: 'Discord', icon: '💬', desc: 'Voice, video, and text messaging' },
  { id: 'netflix', name: 'Netflix', icon: '🍿', desc: 'Movies and TV series streaming' },
  { id: 'twitch', name: 'Twitch', icon: '🟣', desc: 'Live video streaming network' },
  { id: 'twitter', name: 'X / Twitter', icon: '✖️', desc: 'Microblogging platform' },
  { id: 'reddit', name: 'Reddit', icon: '🤖', desc: 'Community forum discussions' },
  { id: 'roblox', name: 'Roblox', icon: '🧱', desc: 'Online gaming and creation' },
  { id: 'minecraft', name: 'Minecraft', icon: '⛏️', desc: 'Multiplayer and auth services' },
];

export const FilteringView: React.FC = () => {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'lists' | 'custom' | 'services' | 'parental'>('lists');

  // Modal states
  const [addListOpen, setAddListOpen] = useState(false);
  const [newListName, setNewListName] = useState('');
  const [newListUrl, setNewListUrl] = useState('');
  const [newListHours, setNewListHours] = useState('24');

  // Custom rules state
  const [customRulesText, setCustomRulesText] = useState('');
  const [rulesLoaded, setRulesLoaded] = useState(false);

  // Simulator check state
  const [checkDomain, setCheckDomain] = useState('');
  const [checkClient, setCheckClient] = useState('');
  const [checkResult, setCheckResult] = useState<FilterCheckResponse | null>(null);

  // Query: Lists
  const { data: filterLists, isLoading: isListsLoading } = useQuery({
    queryKey: ['filter-lists'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/filtering/lists');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Query: Custom Rules
  useQuery({
    queryKey: ['filtering-rules'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/filtering/rules');
      if (res.error || !res.data) throw res.error || new Error('No data');
      if (!rulesLoaded && res.data) {
        setCustomRulesText((res.data.rules || []).join('\n'));
        setRulesLoaded(true);
      }
      return res.data;
    },
  });

  // Query: Default Group (for services and parental)
  const { data: defaultGroup } = useQuery({
    queryKey: ['client-groups', 'default'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/clients/groups');
      const found = res.data?.find((g) => g.name === 'default');
      if (!found) {
        return {
          name: 'default',
          description: 'Default group',
          filtering_enabled: true,
          parental_control: false,
          parental_categories: [],
          safe_search: false,
          blocked_services: [],
        } as ClientGroupDto;
      }
      return found;
    },
  });

  // Mutation: Refresh Lists
  const refreshMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/filtering/refresh');
      if (res.error || !res.data) throw res.error || new Error('Refresh failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: t('filtering.refresh_success'),
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['filter-lists'] });
    },
  });

  // Mutation: Add List
  const addListMutation = useMutation({
    mutationFn: async () => {
      const res = await apiClient.POST('/api/v1/filtering/lists', {
        body: {
          name: newListName,
          url: newListUrl,
          refresh_hours: parseInt(newListHours, 10) || 24,
        },
      });
      if (res.error || !res.data) throw res.error || new Error('Add failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Filter list subscription added',
        color: 'teal',
      });
      setAddListOpen(false);
      setNewListName('');
      setNewListUrl('');
      queryClient.invalidateQueries({ queryKey: ['filter-lists'] });
    },
  });

  // Mutation: Toggle List Enabled
  const toggleListMutation = useMutation({
    mutationFn: async ({ list, enabled }: { list: FilterListDto; enabled: boolean }) => {
      const res = await apiClient.PUT('/api/v1/filtering/lists/{id}', {
        params: { path: { id: list.id } },
        body: {
          name: list.name,
          url: list.url,
          enabled,
          refresh_hours: list.refresh_hours,
        },
      });
      if (res.error || !res.data) throw res.error || new Error('Toggle failed');
      return res.data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['filter-lists'] });
    },
  });

  // Mutation: Delete List
  const deleteListMutation = useMutation({
    mutationFn: async (id: number) => {
      const res = await apiClient.DELETE('/api/v1/filtering/lists/{id}', {
        params: { path: { id } },
      });
      if (res.error || !res.data) throw res.error || new Error('Delete failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Filter list removed',
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['filter-lists'] });
    },
  });

  // Mutation: Save Custom Rules
  const saveRulesMutation = useMutation({
    mutationFn: async (rules: string[]) => {
      const res = await apiClient.PUT('/api/v1/filtering/rules', {
        body: { rules },
      });
      if (res.error || !res.data) throw res.error || new Error('Save rules failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: t('filtering.rules_saved'),
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['filtering-rules'] });
    },
  });

  // Mutation: Check Filtering (Simulator)
  const checkMutation = useMutation({
    mutationFn: async ({ domain, client }: { domain: string; client?: string }) => {
      const res = await apiClient.POST('/api/v1/filtering/check', {
        body: {
          domain,
          client: client || null,
        },
      });
      if (res.error || !res.data) throw res.error || new Error('Check failed');
      return res.data;
    },
    onSuccess: (data) => {
      setCheckResult(data);
    },
  });

  // Mutation: Update Group (Services & Parental)
  const updateGroupMutation = useMutation({
    mutationFn: async (updated: ClientGroupDto) => {
      const res = await apiClient.PUT('/api/v1/clients/groups/{name}', {
        params: { path: { name: updated.name } },
        body: updated,
      });
      if (res.error || !res.data) throw res.error || new Error('Update group failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Group policies updated',
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['client-groups'] });
    },
  });

  const handleSaveCustomRules = () => {
    const lines = customRulesText
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean);
    saveRulesMutation.mutate(lines);
  };

  const handleToggleService = (serviceId: string) => {
    if (!defaultGroup) return;
    const current = defaultGroup.blocked_services || [];
    const next = current.includes(serviceId)
      ? current.filter((s: string) => s !== serviceId)
      : [...current, serviceId];

    updateGroupMutation.mutate({
      ...defaultGroup,
      blocked_services: next,
    });
  };

  const handleToggleCategory = (cat: string) => {
    if (!defaultGroup) return;
    const current = defaultGroup.parental_categories || [];
    const next = current.includes(cat)
      ? current.filter((c: string) => c !== cat)
      : [...current, cat];

    updateGroupMutation.mutate({
      ...defaultGroup,
      parental_control: next.length > 0,
      parental_categories: next,
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
            {t('filtering.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('filtering.subtitle')}
          </p>
        </div>

        {activeTab === 'lists' && (
          <div className="flex items-center space-x-2">
            <button
              type="button"
              onClick={() => refreshMutation.mutate()}
              disabled={refreshMutation.isPending}
              className="inline-flex items-center space-x-2 px-3 py-1.5 text-xs font-semibold rounded-lg border border-gray-300 dark:border-zinc-700 bg-white dark:bg-zinc-800 text-zinc-700 dark:text-zinc-200 hover:bg-gray-50 dark:hover:bg-zinc-700 transition"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${refreshMutation.isPending ? 'animate-spin' : ''}`} />
              <span>{t('filtering.refresh_now')}</span>
            </button>
            <button
              type="button"
              onClick={() => setAddListOpen(true)}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
            >
              <Plus className="h-4 w-4" />
              <span>{t('filtering.add_list')}</span>
            </button>
          </div>
        )}
      </div>

      <div className="flex border-b border-gray-200 dark:border-zinc-800 space-x-6">
        <button
          type="button"
          onClick={() => setActiveTab('lists')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'lists'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <ListFilter className="h-4 w-4" />
          <span>{t('filtering.tab_lists')}</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('custom')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'custom'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <FileCode className="h-4 w-4" />
          <span>{t('filtering.tab_custom_rules')}</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('services')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'services'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <Lock className="h-4 w-4" />
          <span>{t('filtering.tab_services')}</span>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('parental')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'parental'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <Baby className="h-4 w-4" />
          <span>{t('filtering.tab_parental')}</span>
        </button>
      </div>

      {activeTab === 'lists' && (
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50/70 dark:bg-zinc-900/70 font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">{t('common.name')}</th>
                  <th className="py-3 px-4">URL</th>
                  <th className="py-3 px-4">{t('filtering.rules_count')}</th>
                  <th className="py-3 px-4">{t('filtering.last_updated')}</th>
                  <th className="py-3 px-4">{t('common.status')}</th>
                  <th className="py-3 px-4 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
                {isListsLoading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-zinc-400">
                      {t('common.loading')}
                    </td>
                  </tr>
                ) : filterLists && filterLists.length > 0 ? (
                  filterLists.map((list) => {
                    const updatedStr = list.last_updated
                      ? new Date(list.last_updated * 1000).toLocaleString()
                      : 'Never';
                    return (
                      <tr key={list.id} className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/40">
                        <td className="py-3 px-4 font-semibold text-zinc-900 dark:text-white">
                          {list.name}
                        </td>
                        <td className="py-3 px-4 text-zinc-500 dark:text-zinc-400 font-mono truncate max-w-xs" title={list.url}>
                          <a
                            href={list.url}
                            target="_blank"
                            rel="noreferrer"
                            className="hover:underline flex items-center space-x-1"
                          >
                            <span className="truncate">{list.url}</span>
                            <ExternalLink className="h-3 w-3 shrink-0" />
                          </a>
                        </td>
                        <td className="py-3 px-4 font-mono font-semibold text-zinc-800 dark:text-zinc-200">
                          {list.rule_count.toLocaleString()}
                        </td>
                        <td className="py-3 px-4 text-zinc-500 dark:text-zinc-400">
                          {updatedStr}
                        </td>
                        <td className="py-3 px-4">
                          <button
                            type="button"
                            onClick={() =>
                              toggleListMutation.mutate({ list, enabled: !list.enabled })
                            }
                            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold transition ${
                              list.enabled
                                ? 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300'
                                : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400'
                            }`}
                          >
                            {list.enabled ? t('common.enabled') : t('common.disabled')}
                          </button>
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => {
                              if (window.confirm(`Delete list '${list.name}'?`)) {
                                deleteListMutation.mutate(list.id);
                              }
                            }}
                            className="p-1.5 rounded text-zinc-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-950/50 transition"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-zinc-400">
                      No filter lists configured.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'custom' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-4">
            <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
                    {t('filtering.custom_rules_title')}
                  </h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    {t('filtering.custom_rules_desc')}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={handleSaveCustomRules}
                  disabled={saveRulesMutation.isPending}
                  className="inline-flex items-center space-x-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
                >
                  <Save className="h-4 w-4" />
                  <span>{t('filtering.save_rules')}</span>
                </button>
              </div>

              <div className="border border-gray-200 dark:border-zinc-800 rounded-lg overflow-hidden font-mono text-xs">
                <CodeMirror
                  value={customRulesText}
                  height="360px"
                  theme={isDarkMode ? oneDark : undefined}
                  onChange={(val) => setCustomRulesText(val)}
                  placeholder="! Put custom rules here&#10;||example.com^&#10;@@||allowed-shop.com^&#10;127.0.0.1 tracker.bad.net"
                />
              </div>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <div>
              <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
                {t('filtering.test_rule_section')}
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                Simulate filtering verdict against compiled rule trie.
              </p>
            </div>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('common.domain')}
                </label>
                <input
                  type="text"
                  value={checkDomain}
                  onChange={(e) => setCheckDomain(e.target.value)}
                  placeholder={t('filtering.test_domain_placeholder')}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('common.client')} (optional)
                </label>
                <input
                  type="text"
                  value={checkClient}
                  onChange={(e) => setCheckClient(e.target.value)}
                  placeholder={t('filtering.test_client_placeholder')}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <button
                type="button"
                onClick={() => {
                  if (checkDomain.trim()) {
                    checkMutation.mutate({
                      domain: checkDomain.trim(),
                      client: checkClient.trim() || undefined,
                    });
                  }
                }}
                disabled={!checkDomain.trim() || checkMutation.isPending}
                className="w-full inline-flex items-center justify-center space-x-2 px-3 py-2 text-xs font-semibold rounded-lg bg-zinc-800 dark:bg-zinc-700 text-white hover:bg-zinc-700 transition"
              >
                <Play className="h-3.5 w-3.5 text-emerald-400" />
                <span>{t('filtering.test_button')}</span>
              </button>
            </div>

            {checkResult && (
              <div className="pt-3 border-t border-gray-200 dark:border-zinc-800 space-y-2 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-zinc-500">{t('filtering.test_result')}:</span>
                  <span
                    className={`font-bold uppercase px-2 py-0.5 rounded text-[11px] ${
                      checkResult.verdict === 'blocked'
                        ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300'
                        : checkResult.verdict === 'whitelisted'
                        ? 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300'
                        : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300'
                    }`}
                  >
                    {checkResult.verdict}
                  </span>
                </div>
                {checkResult.rule && (
                  <div>
                    <span className="text-zinc-400 block text-[11px]">Matched Rule:</span>
                    <span className="font-mono text-zinc-800 dark:text-zinc-200">
                      {checkResult.rule}
                    </span>
                  </div>
                )}
                {checkResult.list_source && (
                  <div>
                    <span className="text-zinc-400 block text-[11px]">Source List:</span>
                    <span className="text-zinc-800 dark:text-zinc-200">
                      {checkResult.list_source}
                    </span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {activeTab === 'services' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
              {t('filtering.services_title')}
            </h2>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
              {t('filtering.services_desc')}
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {POPULAR_SERVICES.map((srv) => {
              const isBlocked = (defaultGroup?.blocked_services || []).includes(srv.id);
              return (
                <div
                  key={srv.id}
                  className={`p-4 rounded-xl border transition flex items-center justify-between ${
                    isBlocked
                      ? 'bg-rose-50/70 dark:bg-rose-950/20 border-rose-200 dark:border-rose-900/50'
                      : 'bg-white dark:bg-zinc-900 border-gray-200 dark:border-zinc-800'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <span className="text-2xl">{srv.icon}</span>
                    <div>
                      <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">
                        {srv.name}
                      </h3>
                      <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                        {srv.desc}
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => handleToggleService(srv.id)}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                      isBlocked
                        ? 'bg-rose-600 text-white'
                        : 'bg-gray-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-gray-200 dark:hover:bg-zinc-700'
                    }`}
                  >
                    {isBlocked ? 'Blocked' : 'Allow'}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {activeTab === 'parental' && (
        <div className="space-y-6">
          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <div>
              <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
                {t('filtering.parental_title')}
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                {t('filtering.parental_desc')}
              </p>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
              <div className="p-4 rounded-lg border border-gray-200 dark:border-zinc-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">
                    {t('filtering.cat_adult')}
                  </h3>
                  <p className="text-xs text-zinc-500">Blocks known pornographic and adult domains</p>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggleCategory('adult')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    (defaultGroup?.parental_categories || []).includes('adult')
                      ? 'bg-rose-600 text-white'
                      : 'bg-gray-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300'
                  }`}
                >
                  {(defaultGroup?.parental_categories || []).includes('adult') ? 'Blocked' : 'Off'}
                </button>
              </div>

              <div className="p-4 rounded-lg border border-gray-200 dark:border-zinc-800 flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-semibold text-zinc-900 dark:text-white">
                    {t('filtering.cat_gambling')}
                  </h3>
                  <p className="text-xs text-zinc-500">Blocks casinos, sports betting, and lottery sites</p>
                </div>
                <button
                  type="button"
                  onClick={() => handleToggleCategory('gambling')}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    (defaultGroup?.parental_categories || []).includes('gambling')
                      ? 'bg-rose-600 text-white'
                      : 'bg-gray-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300'
                  }`}
                >
                  {(defaultGroup?.parental_categories || []).includes('gambling') ? 'Blocked' : 'Off'}
                </button>
              </div>
            </div>
          </div>

          <div className="p-5 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs space-y-4">
            <div>
              <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
                {t('filtering.safe_search_title')}
              </h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                Rewrites major search engine DNS records to enforce strict SafeSearch modes.
              </p>
            </div>

            <div className="space-y-3 pt-2">
              <div className="p-3 rounded-lg border border-gray-100 dark:border-zinc-800 flex items-center justify-between">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
                  {t('filtering.safe_search_google')}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    if (!defaultGroup) return;
                    updateGroupMutation.mutate({
                      ...defaultGroup,
                      safe_search: !defaultGroup.safe_search,
                    });
                  }}
                  className={`px-3 py-1 rounded-full text-xs font-semibold ${
                    defaultGroup?.safe_search
                      ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300'
                      : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400'
                  }`}
                >
                  {defaultGroup?.safe_search ? 'Active' : 'Disabled'}
                </button>
              </div>
              <div className="p-3 rounded-lg border border-gray-100 dark:border-zinc-800 flex items-center justify-between">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
                  {t('filtering.safe_search_bing')}
                </span>
                <span className="text-[11px] text-zinc-400">Included in SafeSearch policy</span>
              </div>
              <div className="p-3 rounded-lg border border-gray-100 dark:border-zinc-800 flex items-center justify-between">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
                  {t('filtering.safe_search_youtube')}
                </span>
                <span className="text-[11px] text-zinc-400">Included in SafeSearch policy</span>
              </div>
              <div className="p-3 rounded-lg border border-gray-100 dark:border-zinc-800 flex items-center justify-between">
                <span className="text-xs font-medium text-zinc-800 dark:text-zinc-200">
                  {t('filtering.safe_search_duckduckgo')}
                </span>
                <span className="text-[11px] text-zinc-400">Included in SafeSearch policy</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {addListOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4">
            <h2 className="text-lg font-bold text-zinc-900 dark:text-white">
              {t('filtering.add_list_modal_title')}
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('filtering.list_name')}
                </label>
                <input
                  type="text"
                  value={newListName}
                  onChange={(e) => setNewListName(e.target.value)}
                  placeholder="e.g. StevenBlack Unified Hosts"
                  className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('filtering.list_url')}
                </label>
                <input
                  type="url"
                  value={newListUrl}
                  onChange={(e) => setNewListUrl(e.target.value)}
                  placeholder="https://raw.githubusercontent.com/..."
                  className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('filtering.refresh_hours')}
                </label>
                <input
                  type="number"
                  min="1"
                  max="168"
                  value={newListHours}
                  onChange={(e) => setNewListHours(e.target.value)}
                  className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                type="button"
                onClick={() => setAddListOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (newListName.trim() && newListUrl.trim()) {
                    addListMutation.mutate();
                  }
                }}
                disabled={!newListName.trim() || !newListUrl.trim() || addListMutation.isPending}
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
