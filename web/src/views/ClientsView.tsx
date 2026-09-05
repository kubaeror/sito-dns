import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useTranslation } from 'react-i18next';
import { notifications } from '@mantine/notifications';
import {
  Users,
  Radio,
  Layers,
  Plus,
  Trash2,
  Edit2,
} from 'lucide-react';
import apiClient from '../api/client';
import type { ClientDto, ClientGroupDto } from '../api/types';

export const ClientsView: React.FC = () => {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'clients' | 'discovered' | 'groups'>('clients');

  // Modals state
  const [clientModalOpen, setClientModalOpen] = useState(false);
  const [editingClient, setEditingClient] = useState<ClientDto | null>(null);
  const [clientName, setClientName] = useState('');
  const [clientIps, setClientIps] = useState('');
  const [clientSubnets, setClientSubnets] = useState('');
  const [clientMacs, setClientMacs] = useState('');
  const [clientGroup, setClientGroup] = useState('default');
  const [clientDotSni, setClientDotSni] = useState('');
  const [clientDohPath, setClientDohPath] = useState('');
  const [ignoreQueryLog, setIgnoreQueryLog] = useState(false);
  const [ignoreStats, setIgnoreStats] = useState(false);

  // Group modal state
  const [groupModalOpen, setGroupModalOpen] = useState(false);
  const [editingGroup, setEditingGroup] = useState<ClientGroupDto | null>(null);
  const [groupName, setGroupName] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [groupFiltering, setGroupFiltering] = useState(true);
  const [groupParental, setGroupParental] = useState(false);
  const [groupSafeSearch, setGroupSafeSearch] = useState(false);

  // Query: Clients
  const { data: clients, isLoading: isClientsLoading } = useQuery({
    queryKey: ['clients'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/clients');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Query: Groups
  const { data: groups } = useQuery({
    queryKey: ['client-groups'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/clients/groups');
      if (res.error || !res.data) throw res.error || new Error('No data');
      return res.data;
    },
  });

  // Query: Recent queries to detect unconfigured clients
  const { data: recentLogs } = useQuery({
    queryKey: ['recent-logs-for-discovery'],
    queryFn: async () => {
      const res = await apiClient.GET('/api/v1/querylog', {
        params: { query: { limit: 100 } },
      });
      return res.data?.entries || [];
    },
  });

  // Discovered devices derived from query log where client is not yet registered
  const discoveredDevices = React.useMemo(() => {
    if (!recentLogs) return [];
    const registeredIps = new Set<string>();
    clients?.forEach((c) => {
      c.ip?.forEach((ip) => registeredIps.add(ip));
    });

    const discoveredMap = new Map<string, { ip: string; name?: string; count: number }>();
    recentLogs.forEach((entry) => {
      if (!registeredIps.has(entry.client_ip)) {
        const existing = discoveredMap.get(entry.client_ip);
        if (existing) {
          existing.count += 1;
        } else {
          discoveredMap.set(entry.client_ip, {
            ip: entry.client_ip,
            name: entry.client_name || undefined,
            count: 1,
          });
        }
      }
    });

    return Array.from(discoveredMap.values());
  }, [recentLogs, clients]);

  // Mutation: Save Client (Create or Update)
  const saveClientMutation = useMutation({
    mutationFn: async () => {
      const payload: ClientDto = {
        name: clientName.trim(),
        ip: clientIps.split(',').map((s) => s.trim()).filter(Boolean),
        subnet: clientSubnets.split(',').map((s) => s.trim()).filter(Boolean),
        mac: clientMacs.split(',').map((s) => s.trim()).filter(Boolean),
        group: clientGroup || 'default',
        dot_sni: clientDotSni.trim() || null,
        doh_path: clientDohPath.trim() || null,
        ignore_query_log: ignoreQueryLog,
        ignore_stats: ignoreStats,
      };

      if (editingClient) {
        const res = await apiClient.PUT('/api/v1/clients/{name}', {
          params: { path: { name: editingClient.name } },
          body: payload,
        });
        if (res.error || !res.data) throw res.error || new Error('Update failed');
        return res.data;
      } else {
        const res = await apiClient.POST('/api/v1/clients', {
          body: payload,
        });
        if (res.error || !res.data) throw res.error || new Error('Create failed');
        return res.data;
      }
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: editingClient ? 'Client updated' : 'Client registered',
        color: 'teal',
      });
      setClientModalOpen(false);
      resetClientForm();
      queryClient.invalidateQueries({ queryKey: ['clients'] });
    },
  });

  // Mutation: Delete Client
  const deleteClientMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await apiClient.DELETE('/api/v1/clients/{name}', {
        params: { path: { name } },
      });
      if (res.error || !res.data) throw res.error || new Error('Delete failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Client removed',
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['clients'] });
    },
  });

  // Mutation: Save Group
  const saveGroupMutation = useMutation({
    mutationFn: async () => {
      const payload: ClientGroupDto = {
        name: groupName.trim(),
        description: groupDesc.trim() || null,
        filtering_enabled: groupFiltering,
        parental_control: groupParental,
        parental_categories: editingGroup?.parental_categories || [],
        safe_search: groupSafeSearch,
        blocked_services: editingGroup?.blocked_services || [],
      };

      if (editingGroup) {
        const res = await apiClient.PUT('/api/v1/clients/groups/{name}', {
          params: { path: { name: editingGroup.name } },
          body: payload,
        });
        if (res.error || !res.data) throw res.error || new Error('Update failed');
        return res.data;
      } else {
        const res = await apiClient.POST('/api/v1/clients/groups', {
          body: payload,
        });
        if (res.error || !res.data) throw res.error || new Error('Create failed');
        return res.data;
      }
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Group saved',
        color: 'teal',
      });
      setGroupModalOpen(false);
      resetGroupForm();
      queryClient.invalidateQueries({ queryKey: ['client-groups'] });
    },
  });

  // Mutation: Delete Group
  const deleteGroupMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await apiClient.DELETE('/api/v1/clients/groups/{name}', {
        params: { path: { name } },
      });
      if (res.error || !res.data) throw res.error || new Error('Delete failed');
      return res.data;
    },
    onSuccess: () => {
      notifications.show({
        title: t('common.success'),
        message: 'Group removed',
        color: 'teal',
      });
      queryClient.invalidateQueries({ queryKey: ['client-groups'] });
    },
  });

  const resetClientForm = () => {
    setEditingClient(null);
    setClientName('');
    setClientIps('');
    setClientSubnets('');
    setClientMacs('');
    setClientGroup('default');
    setClientDotSni('');
    setClientDohPath('');
    setIgnoreQueryLog(false);
    setIgnoreStats(false);
  };

  const openEditClient = (c: ClientDto) => {
    setEditingClient(c);
    setClientName(c.name);
    setClientIps(c.ip?.join(', ') || '');
    setClientSubnets(c.subnet?.join(', ') || '');
    setClientMacs(c.mac?.join(', ') || '');
    setClientGroup(c.group || 'default');
    setClientDotSni(c.dot_sni || '');
    setClientDohPath(c.doh_path || '');
    setIgnoreQueryLog(c.ignore_query_log || false);
    setIgnoreStats(c.ignore_stats || false);
    setClientModalOpen(true);
  };

  const handleAddDiscovered = (dev: { ip: string; name?: string }) => {
    resetClientForm();
    setClientName(dev.name || `Client-${dev.ip.replace(/[^0-9a-zA-Z]/g, '-')}`);
    setClientIps(dev.ip);
    setClientModalOpen(true);
  };

  const resetGroupForm = () => {
    setEditingGroup(null);
    setGroupName('');
    setGroupDesc('');
    setGroupFiltering(true);
    setGroupParental(false);
    setGroupSafeSearch(false);
  };

  const openEditGroup = (g: ClientGroupDto) => {
    setEditingGroup(g);
    setGroupName(g.name);
    setGroupDesc(g.description || '');
    setGroupFiltering(g.filtering_enabled ?? true);
    setGroupParental(g.parental_control ?? false);
    setGroupSafeSearch(g.safe_search ?? false);
    setGroupModalOpen(true);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-white">
            {t('clients.title')}
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            {t('clients.subtitle')}
          </p>
        </div>

        {activeTab === 'clients' && (
          <button
            type="button"
            onClick={() => {
              resetClientForm();
              setClientModalOpen(true);
            }}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
          >
            <Plus className="h-4 w-4" />
            <span>{t('clients.add_client')}</span>
          </button>
        )}

        {activeTab === 'groups' && (
          <button
            type="button"
            onClick={() => {
              resetGroupForm();
              setGroupModalOpen(true);
            }}
            className="inline-flex items-center space-x-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
          >
            <Plus className="h-4 w-4" />
            <span>{t('clients.add_group')}</span>
          </button>
        )}
      </div>

      <div className="flex border-b border-gray-200 dark:border-zinc-800 space-x-6">
        <button
          type="button"
          onClick={() => setActiveTab('clients')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'clients'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <Users className="h-4 w-4" />
          <span>{t('clients.tab_clients')}</span>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('discovered')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'discovered'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <Radio className="h-4 w-4" />
          <span>{t('clients.tab_discovered')}</span>
          {discoveredDevices.length > 0 && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 font-bold">
              {discoveredDevices.length}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('groups')}
          className={`pb-3 text-sm font-semibold flex items-center space-x-2 border-b-2 transition ${
            activeTab === 'groups'
              ? 'border-emerald-600 text-emerald-600 dark:text-emerald-400'
              : 'border-transparent text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200'
          }`}
        >
          <Layers className="h-4 w-4" />
          <span>{t('clients.tab_groups')}</span>
        </button>
      </div>

      {activeTab === 'clients' && (
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50/70 dark:bg-zinc-900/70 font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">{t('common.name')}</th>
                  <th className="py-3 px-4">{t('common.ip')}</th>
                  <th className="py-3 px-4">{t('common.mac')}</th>
                  <th className="py-3 px-4">Group</th>
                  <th className="py-3 px-4">Identifiers</th>
                  <th className="py-3 px-4 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
                {isClientsLoading ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-zinc-400">
                      {t('common.loading')}
                    </td>
                  </tr>
                ) : clients && clients.length > 0 ? (
                  clients.map((client) => (
                    <tr key={client.name} className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/40">
                      <td className="py-3 px-4 font-semibold text-zinc-900 dark:text-white">
                        {client.name}
                      </td>
                      <td className="py-3 px-4 font-mono text-zinc-700 dark:text-zinc-300">
                        {client.ip?.join(', ') || '—'}
                      </td>
                      <td className="py-3 px-4 font-mono text-zinc-500 dark:text-zinc-400">
                        {client.mac?.join(', ') || '—'}
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-0.5 rounded text-[11px] bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-medium">
                          {client.group}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-zinc-500 text-[11px] font-mono">
                        {client.dot_sni ? `SNI: ${client.dot_sni}` : ''}
                        {client.doh_path ? ` Path: ${client.doh_path}` : ''}
                        {!client.dot_sni && !client.doh_path && '—'}
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          type="button"
                          onClick={() => openEditClient(client)}
                          className="p-1 rounded text-zinc-500 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/50"
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            if (window.confirm(t('clients.delete_client_confirm', { name: client.name }))) {
                              deleteClientMutation.mutate(client.name);
                            }
                          }}
                          className="p-1 rounded text-zinc-500 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-zinc-400">
                      {t('clients.no_clients')}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === 'discovered' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 shadow-xs">
            <h2 className="text-base font-semibold text-zinc-900 dark:text-white">
              {t('clients.tab_discovered')}
            </h2>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
              {t('clients.discovered_desc')}
            </p>
          </div>

          <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50/70 dark:bg-zinc-900/70 font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                  <tr>
                    <th className="py-3 px-4">{t('common.ip')}</th>
                    <th className="py-3 px-4">Hostname / Name</th>
                    <th className="py-3 px-4">Activity (Queries)</th>
                    <th className="py-3 px-4 text-right">{t('common.actions')}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
                  {discoveredDevices.length > 0 ? (
                    discoveredDevices.map((dev) => (
                      <tr key={dev.ip} className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/40">
                        <td className="py-3 px-4 font-mono font-semibold text-zinc-900 dark:text-white">
                          {dev.ip}
                        </td>
                        <td className="py-3 px-4 text-zinc-600 dark:text-zinc-300">
                          {dev.name || 'Unknown Host'}
                        </td>
                        <td className="py-3 px-4 font-mono text-zinc-500">
                          {dev.count} queries seen
                        </td>
                        <td className="py-3 px-4 text-right">
                          <button
                            type="button"
                            onClick={() => handleAddDiscovered(dev)}
                            className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-emerald-50 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 hover:bg-emerald-100 transition"
                          >
                            <Plus className="h-3 w-3" />
                            <span>{t('clients.add_as_client')}</span>
                          </button>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-zinc-400">
                        {t('clients.no_discovered')}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'groups' && (
        <div className="rounded-xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-xs overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-gray-200 dark:border-zinc-800 bg-gray-50/70 dark:bg-zinc-900/70 font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">{t('clients.group_name')}</th>
                  <th className="py-3 px-4">{t('clients.group_desc')}</th>
                  <th className="py-3 px-4">Filtering</th>
                  <th className="py-3 px-4">Parental</th>
                  <th className="py-3 px-4">SafeSearch</th>
                  <th className="py-3 px-4 text-right">{t('common.actions')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-zinc-800">
                {groups && groups.length > 0 ? (
                  groups.map((grp) => (
                    <tr key={grp.name} className="hover:bg-gray-50/80 dark:hover:bg-zinc-800/40">
                      <td className="py-3 px-4 font-semibold text-zinc-900 dark:text-white">
                        {grp.name}
                      </td>
                      <td className="py-3 px-4 text-zinc-500">
                        {grp.description || '—'}
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          grp.filtering_enabled ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300' : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500'
                        }`}>
                          {grp.filtering_enabled ? 'ON' : 'OFF'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          grp.parental_control ? 'bg-rose-100 dark:bg-rose-950 text-rose-700 dark:text-rose-300' : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500'
                        }`}>
                          {grp.parental_control ? 'ACTIVE' : 'OFF'}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          grp.safe_search ? 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300' : 'bg-zinc-100 dark:bg-zinc-800 text-zinc-500'
                        }`}>
                          {grp.safe_search ? 'ENFORCED' : 'OFF'}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right space-x-2">
                        <button
                          type="button"
                          onClick={() => openEditGroup(grp)}
                          className="p-1 rounded text-zinc-500 hover:text-emerald-600 hover:bg-emerald-50 dark:hover:bg-emerald-950/50"
                        >
                          <Edit2 className="h-3.5 w-3.5" />
                        </button>
                        {grp.name !== 'default' && (
                          <button
                            type="button"
                            onClick={() => {
                              if (window.confirm(t('clients.delete_group_confirm', { name: grp.name }))) {
                                deleteGroupMutation.mutate(grp.name);
                              }
                            }}
                            className="p-1 rounded text-zinc-500 hover:text-rose-600 hover:bg-rose-50 dark:hover:bg-rose-950/50"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-zinc-400">
                      No groups configured.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {clientModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4">
            <h2 className="text-lg font-bold text-zinc-900 dark:text-white">
              {editingClient ? t('clients.edit_client') : t('clients.add_client')}
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('clients.client_name')}
                </label>
                <input
                  type="text"
                  value={clientName}
                  onChange={(e) => setClientName(e.target.value)}
                  placeholder="e.g. MacBook Pro, Office PC"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('clients.client_ip')}
                </label>
                <input
                  type="text"
                  value={clientIps}
                  onChange={(e) => setClientIps(e.target.value)}
                  placeholder="192.168.1.50, 192.168.1.51"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('clients.client_subnet')}
                  </label>
                  <input
                    type="text"
                    value={clientSubnets}
                    onChange={(e) => setClientSubnets(e.target.value)}
                    placeholder="192.168.1.0/24"
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('clients.client_mac')}
                  </label>
                  <input
                    type="text"
                    value={clientMacs}
                    onChange={(e) => setClientMacs(e.target.value)}
                    placeholder="aa:bb:cc:dd:ee:ff"
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('clients.client_group')}
                </label>
                <select
                  value={clientGroup}
                  onChange={(e) => setClientGroup(e.target.value)}
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                >
                  <option value="default">default</option>
                  {groups
                    ?.filter((g) => g.name !== 'default')
                    .map((g) => (
                      <option key={g.name} value={g.name}>
                        {g.name}
                      </option>
                    ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('clients.client_dot_sni')}
                  </label>
                  <input
                    type="text"
                    value={clientDotSni}
                    onChange={(e) => setClientDotSni(e.target.value)}
                    placeholder="laptop.lan"
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('clients.client_doh_path')}
                  </label>
                  <input
                    type="text"
                    value={clientDohPath}
                    onChange={(e) => setClientDohPath(e.target.value)}
                    placeholder="/dns-query/laptop"
                    className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3">
              <button
                type="button"
                onClick={() => setClientModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (clientName.trim()) {
                    saveClientMutation.mutate();
                  }
                }}
                disabled={!clientName.trim() || saveClientMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
              >
                {t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}

      {groupModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/50 backdrop-blur-xs">
          <div className="w-full max-w-md rounded-2xl bg-white dark:bg-zinc-900 border border-gray-200 dark:border-zinc-800 p-6 shadow-xl space-y-4">
            <h2 className="text-lg font-bold text-zinc-900 dark:text-white">
              {editingGroup ? t('clients.edit_group') : t('clients.add_group')}
            </h2>

            <div className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('clients.group_name')}
                </label>
                <input
                  type="text"
                  value={groupName}
                  disabled={Boolean(editingGroup)}
                  onChange={(e) => setGroupName(e.target.value)}
                  placeholder="e.g. kids, guest, iot"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white disabled:opacity-50"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                  {t('clients.group_desc')}
                </label>
                <input
                  type="text"
                  value={groupDesc}
                  onChange={(e) => setGroupDesc(e.target.value)}
                  placeholder="Description of policy group"
                  className="w-full px-3 py-1.5 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                />
              </div>

              <div className="space-y-2 pt-2">
                <label className="flex items-center space-x-2 text-xs text-zinc-800 dark:text-zinc-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={groupFiltering}
                    onChange={(e) => setGroupFiltering(e.target.checked)}
                    className="rounded border-gray-300 text-emerald-600 focus:ring-emerald-500"
                  />
                  <span>{t('clients.filtering_enabled')}</span>
                </label>

                <label className="flex items-center space-x-2 text-xs text-zinc-800 dark:text-zinc-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={groupParental}
                    onChange={(e) => setGroupParental(e.target.checked)}
                    className="rounded border-gray-300 text-emerald-600 focus:ring-emerald-500"
                  />
                  <span>{t('clients.parental_enabled')}</span>
                </label>

                <label className="flex items-center space-x-2 text-xs text-zinc-800 dark:text-zinc-200 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={groupSafeSearch}
                    onChange={(e) => setGroupSafeSearch(e.target.checked)}
                    className="rounded border-gray-300 text-emerald-600 focus:ring-emerald-500"
                  />
                  <span>{t('clients.safe_search_enabled')}</span>
                </label>
              </div>
            </div>

            <div className="flex items-center justify-end space-x-3 pt-3">
              <button
                type="button"
                onClick={() => setGroupModalOpen(false)}
                className="px-4 py-2 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                {t('common.cancel')}
              </button>
              <button
                type="button"
                onClick={() => {
                  if (groupName.trim()) {
                    saveGroupMutation.mutate();
                  }
                }}
                disabled={!groupName.trim() || saveGroupMutation.isPending}
                className="px-4 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
              >
                {t('common.save')}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
