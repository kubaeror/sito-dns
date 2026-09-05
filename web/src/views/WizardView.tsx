import React, { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';
import { notifications } from '@mantine/notifications';
import {
  Languages,
  UserCheck,
  Radio,
  Server,
  ListFilter,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Copy,
  Check,
  AlertTriangle,
} from 'lucide-react';
import apiClient from '../api/client';
import { useAuthStore } from '../stores/authStore';

const UPSTREAM_PRESETS = [
  {
    id: 'quad9',
    name: 'Quad9',
    desc: 'Malware blocking & Anycast DNSSEC',
    servers: ['9.9.9.9:53', '149.112.112.112:53'],
  },
  {
    id: 'cloudflare',
    name: 'Cloudflare',
    desc: 'Fastest Anycast response time, privacy-first',
    servers: ['1.1.1.1:53', '1.0.0.1:53'],
  },
  {
    id: 'adguard',
    name: 'AdGuard DNS',
    desc: 'Upstream ad & tracker blocking',
    servers: ['94.140.14.14:53', '94.140.15.15:53'],
  },
  {
    id: 'google',
    name: 'Google Public DNS',
    desc: 'Global Anycast high availability',
    servers: ['8.8.8.8:53', '8.8.4.4:53'],
  },
];

const RECOMMENDED_LISTS = [
  {
    id: 'stevenblack',
    name: 'StevenBlack Unified Hosts',
    url: 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',
    desc: 'Comprehensive protection against adware and malware domains',
    defaultChecked: true,
  },
  {
    id: 'adguard_dns',
    name: 'AdGuard DNS Filter',
    url: 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',
    desc: 'High-precision blocklist targeting tracking scripts and telemetry',
    defaultChecked: true,
  },
  {
    id: 'easylist',
    name: 'EasyList',
    url: 'https://easylist.to/easylist/easylist.txt',
    desc: 'Standard adblock filter rules for web and app services',
    defaultChecked: false,
  },
];

export const WizardView: React.FC = () => {
  const { t, i18n } = useTranslation();
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [currentStep, setCurrentStep] = useState(1);

  // Step 2: Admin
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Step 3: Ports
  const [dnsPort, setDnsPort] = useState(53);
  const [webPort, setWebPort] = useState(3000);

  // Step 4: Upstreams
  const [selectedPreset, setSelectedPreset] = useState('quad9');
  const [testedLatency, setTestedLatency] = useState<number | null>(null);
  const [isTestingLatency, setIsTestingLatency] = useState(false);

  // Step 5: Lists
  const [selectedLists, setSelectedLists] = useState<string[]>(['stevenblack', 'adguard_dns']);

  // Handle language switch
  const selectLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  // Live RTT test for upstreams
  const handleTestPreset = async (servers: string[]) => {
    setIsTestingLatency(true);
    setTestedLatency(null);
    try {
      const res = await apiClient.POST('/api/v1/upstream/test', {
        body: {
          servers,
        },
      });
      if (res.data?.results && res.data.results.length > 0) {
        const first = res.data.results[0];
        setTestedLatency(first.rtt_ms ?? null);
      }
    } catch {
      // ignore
    } finally {
      setIsTestingLatency(false);
    }
  };

  // Finalize setup
  const handleFinish = async () => {
    try {
      // 1. Save Upstreams
      const preset = UPSTREAM_PRESETS.find((p) => p.id === selectedPreset);
      const chosenServers = preset?.servers || ['9.9.9.9:53'];

      await apiClient.PUT('/api/v1/upstream', {
        body: {
          servers: chosenServers,
          bootstrap: ['9.9.9.9', '1.1.1.1'],
          strategy: 'failover',
          timeout_ms: 5000,
          probe_domain: 'example.com',
          pool_size: 4,
        },
      });

      // 2. Save selected filter lists
      for (const listId of selectedLists) {
        const rec = RECOMMENDED_LISTS.find((l) => l.id === listId);
        if (rec) {
          try {
            await apiClient.POST('/api/v1/filtering/lists', {
              body: {
                name: rec.name,
                url: rec.url,
                refresh_hours: 24,
              },
            });
          } catch {
            // list might already exist
          }
        }
      }

      // 3. Mark admin authenticated
      if (username) {
        setAuth(username, 'admin', null);
      }

      notifications.show({
        title: t('common.success'),
        message: 'sito setup completed successfully!',
        color: 'teal',
      });

      navigate('/');
    } catch {
      navigate('/');
    }
  };

  const nextStep = () => {
    if (currentStep === 2) {
      if (password && password !== confirmPassword) {
        notifications.show({
          title: t('common.error'),
          message: t('wizard.passwords_mismatch'),
          color: 'red',
        });
        return;
      }
    }
    setCurrentStep((prev) => Math.min(prev + 1, 6));
  };

  const prevStep = () => {
    setCurrentStep((prev) => Math.max(prev - 1, 1));
  };

  const stepsHeader = [
    { num: 1, label: t('wizard.step1'), icon: Languages },
    { num: 2, label: t('wizard.step2'), icon: UserCheck },
    { num: 3, label: t('wizard.step3'), icon: Radio },
    { num: 4, label: t('wizard.step4'), icon: Server },
    { num: 5, label: t('wizard.step5'), icon: ListFilter },
    { num: 6, label: t('wizard.step6'), icon: CheckCircle2 },
  ];

  return (
    <div className="min-h-screen flex flex-col justify-center items-center py-12 px-4 sm:px-6 lg:px-8 bg-gray-50 dark:bg-zinc-950">
      <div className="w-full max-w-3xl space-y-8">
        {/* Logo & Header */}
        <div className="text-center">
          <div className="mx-auto h-12 w-12 rounded-xl bg-emerald-600 flex items-center justify-center text-white shadow-md shadow-emerald-600/30">
            <CheckCircle2 className="h-7 w-7" />
          </div>
          <h1 className="mt-4 text-3xl font-extrabold tracking-tight text-zinc-900 dark:text-white">
            {t('wizard.title')}
          </h1>
          <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">
            {t('wizard.subtitle')}
          </p>
        </div>

        {/* Progress Bar / Stepper */}
        <div className="hidden sm:flex items-center justify-between relative">
          <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-gray-200 dark:bg-zinc-800 -translate-y-1/2 z-0" />
          {stepsHeader.map((step) => {
            const isDone = currentStep > step.num;
            const isCurrent = currentStep === step.num;
            const Icon = step.icon;
            return (
              <div key={step.num} className="relative z-10 flex flex-col items-center">
                <div
                  className={`h-9 w-9 rounded-full flex items-center justify-center text-xs font-bold transition ${
                    isDone
                      ? 'bg-emerald-600 text-white'
                      : isCurrent
                      ? 'bg-emerald-500 text-white ring-4 ring-emerald-100 dark:ring-emerald-950'
                      : 'bg-white dark:bg-zinc-900 text-zinc-400 border border-gray-300 dark:border-zinc-700'
                  }`}
                >
                  {isDone ? <Check className="h-4 w-4" /> : <Icon className="h-4 w-4" />}
                </div>
                <span className={`mt-1.5 text-[11px] font-medium ${isCurrent ? 'text-emerald-600 font-semibold' : 'text-zinc-500'}`}>
                  {step.label}
                </span>
              </div>
            );
          })}
        </div>

        {/* Step Content Container */}
        <div className="rounded-2xl border border-gray-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-8 shadow-sm">
          {/* STEP 1: Language */}
          {currentStep === 1 && (
            <div className="space-y-6 text-center">
              <div>
                <h2 className="text-xl font-bold text-zinc-900 dark:text-white">
                  {t('wizard.step1_title')}
                </h2>
                <p className="text-xs text-zinc-500 mt-1">
                  {t('wizard.step1_desc')}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-4 max-w-md mx-auto pt-4">
                <button
                  type="button"
                  onClick={() => selectLanguage('en')}
                  className={`p-5 rounded-xl border text-center transition flex flex-col items-center justify-center space-y-2 ${
                    i18n.language.startsWith('en')
                      ? 'border-emerald-600 bg-emerald-50/50 dark:bg-emerald-950/20 text-emerald-900 dark:text-emerald-100 ring-2 ring-emerald-500'
                      : 'border-gray-200 dark:border-zinc-800 hover:border-gray-300 text-zinc-800 dark:text-zinc-200'
                  }`}
                >
                  <span className="text-3xl">🇬🇧</span>
                  <span className="text-sm font-bold">English</span>
                  <span className="text-[11px] text-zinc-500">Default International</span>
                </button>

                <button
                  type="button"
                  onClick={() => selectLanguage('pl')}
                  className={`p-5 rounded-xl border text-center transition flex flex-col items-center justify-center space-y-2 ${
                    i18n.language.startsWith('pl')
                      ? 'border-emerald-600 bg-emerald-50/50 dark:bg-emerald-950/20 text-emerald-900 dark:text-emerald-100 ring-2 ring-emerald-500'
                      : 'border-gray-200 dark:border-zinc-800 hover:border-gray-300 text-zinc-800 dark:text-zinc-200'
                  }`}
                >
                  <span className="text-3xl">🇵🇱</span>
                  <span className="text-sm font-bold">Polski</span>
                  <span className="text-[11px] text-zinc-500">Język polski</span>
                </button>
              </div>
            </div>
          )}

          {/* STEP 2: Admin Account */}
          {currentStep === 2 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-zinc-900 dark:text-white">
                  {t('wizard.step2_title')}
                </h2>
                <p className="text-xs text-zinc-500 mt-1">
                  {t('wizard.step2_desc')}
                </p>
              </div>

              <div className="space-y-4 max-w-md mx-auto">
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('wizard.admin_username')}
                  </label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('wizard.admin_password')}
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    {t('wizard.admin_confirm_password')}
                  </label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••••••"
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white"
                  />
                </div>
              </div>
            </div>
          )}

          {/* STEP 3: Listeners & Ports */}
          {currentStep === 3 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-zinc-900 dark:text-white">
                  {t('wizard.step3_title')}
                </h2>
                <p className="text-xs text-zinc-500 mt-1">
                  {t('wizard.step3_desc')}
                </p>
              </div>

              <div className="p-3.5 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-800 text-xs text-amber-800 dark:text-amber-300 flex items-start space-x-2.5">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 mt-0.5" />
                <p>{t('wizard.port_53_notice')}</p>
              </div>

              <div className="grid grid-cols-2 gap-4 max-w-md mx-auto pt-2">
                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    DNS Port (UDP / TCP)
                  </label>
                  <input
                    type="number"
                    value={dnsPort}
                    onChange={(e) => setDnsPort(parseInt(e.target.value, 10) || 53)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono font-semibold"
                  />
                </div>

                <div>
                  <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300 mb-1">
                    Web Admin Port
                  </label>
                  <input
                    type="number"
                    value={webPort}
                    onChange={(e) => setWebPort(parseInt(e.target.value, 10) || 3000)}
                    className="w-full px-3 py-2 text-xs rounded-lg border border-gray-300 dark:border-zinc-700 bg-gray-50 dark:bg-zinc-800 text-zinc-900 dark:text-white font-mono font-semibold"
                  />
                </div>
              </div>
            </div>
          )}

          {/* STEP 4: Upstreams */}
          {currentStep === 4 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-zinc-900 dark:text-white">
                  {t('wizard.step4_title')}
                </h2>
                <p className="text-xs text-zinc-500 mt-1">
                  {t('wizard.step4_desc')}
                </p>
              </div>

              <div className="space-y-3">
                {UPSTREAM_PRESETS.map((p) => (
                  <div
                    key={p.id}
                    onClick={() => {
                      setSelectedPreset(p.id);
                      handleTestPreset(p.servers);
                    }}
                    className={`p-4 rounded-xl border cursor-pointer transition flex items-center justify-between ${
                      selectedPreset === p.id
                        ? 'border-emerald-600 bg-emerald-50/40 dark:bg-emerald-950/20 ring-1 ring-emerald-500'
                        : 'border-gray-200 dark:border-zinc-800 hover:border-gray-300'
                    }`}
                  >
                    <div>
                      <h3 className="text-sm font-bold text-zinc-900 dark:text-white">
                        {p.name}
                      </h3>
                      <p className="text-xs text-zinc-500">{p.desc}</p>
                      <span className="font-mono text-[11px] text-zinc-400 mt-0.5 block">
                        {p.servers.join(', ')}
                      </span>
                    </div>

                    {selectedPreset === p.id && (
                      <div className="flex items-center space-x-2">
                        {isTestingLatency ? (
                          <span className="text-xs text-zinc-500 animate-pulse">Measuring...</span>
                        ) : testedLatency !== null ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 text-xs font-mono font-bold">
                            {testedLatency} ms
                          </span>
                        ) : null}
                        <Check className="h-4 w-4 text-emerald-600" />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* STEP 5: Initial Blocklists */}
          {currentStep === 5 && (
            <div className="space-y-6">
              <div>
                <h2 className="text-xl font-bold text-zinc-900 dark:text-white">
                  {t('wizard.step5_title')}
                </h2>
                <p className="text-xs text-zinc-500 mt-1">
                  {t('wizard.step5_desc')}
                </p>
              </div>

              <div className="space-y-3">
                {RECOMMENDED_LISTS.map((list) => {
                  const isChecked = selectedLists.includes(list.id);
                  return (
                    <div
                      key={list.id}
                      onClick={() => {
                        setSelectedLists((prev) =>
                          isChecked ? prev.filter((id) => id !== list.id) : [...prev, list.id]
                        );
                      }}
                      className={`p-4 rounded-xl border cursor-pointer transition flex items-start space-x-3 ${
                        isChecked
                          ? 'border-emerald-600 bg-emerald-50/40 dark:bg-emerald-950/20'
                          : 'border-gray-200 dark:border-zinc-800'
                      }`}
                    >
                      <input
                        type="checkbox"
                        checked={isChecked}
                        onChange={() => {}}
                        className="mt-1 rounded text-emerald-600 focus:ring-emerald-500"
                      />
                      <div className="flex-1">
                        <h3 className="text-sm font-bold text-zinc-900 dark:text-white">
                          {list.name}
                        </h3>
                        <p className="text-xs text-zinc-500 mt-0.5">{list.desc}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* STEP 6: Summary & Finish */}
          {currentStep === 6 && (
            <div className="space-y-6 text-center">
              <div>
                <div className="mx-auto h-12 w-12 rounded-full bg-emerald-100 dark:bg-emerald-950 flex items-center justify-center text-emerald-600 dark:text-emerald-400 mb-2">
                  <Check className="h-6 w-6" />
                </div>
                <h2 className="text-xl font-bold text-zinc-900 dark:text-white">
                  {t('wizard.step6_title')}
                </h2>
                <p className="text-xs text-zinc-500 mt-1">
                  {t('wizard.step6_desc')}
                </p>
              </div>

              <div className="space-y-3 text-left max-w-lg mx-auto">
                <div>
                  <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 block mb-1">
                    {t('wizard.test_command_label')}
                  </span>
                  <div className="p-3 rounded-lg bg-zinc-950 font-mono text-xs text-emerald-400 flex items-center justify-between">
                    <span>dig @127.0.0.1 -p {dnsPort} example.com</span>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(`dig @127.0.0.1 -p ${dnsPort} example.com`);
                        notifications.show({ message: t('common.copied'), color: 'teal' });
                      }}
                      className="text-zinc-500 hover:text-white"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>

                <div>
                  <span className="text-xs font-semibold text-zinc-700 dark:text-zinc-300 block mb-1">
                    {t('wizard.test_blocked_label')}
                  </span>
                  <div className="p-3 rounded-lg bg-zinc-950 font-mono text-xs text-emerald-400 flex items-center justify-between">
                    <span>dig @127.0.0.1 -p {dnsPort} doubleclick.net</span>
                    <button
                      type="button"
                      onClick={() => {
                        navigator.clipboard.writeText(`dig @127.0.0.1 -p ${dnsPort} doubleclick.net`);
                        notifications.show({ message: t('common.copied'), color: 'teal' });
                      }}
                      className="text-zinc-500 hover:text-white"
                    >
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Stepper Navigation Buttons */}
          <div className="flex items-center justify-between pt-6 mt-6 border-t border-gray-200 dark:border-zinc-800">
            {currentStep > 1 ? (
              <button
                type="button"
                onClick={prevStep}
                className="inline-flex items-center space-x-1 px-4 py-2 text-xs font-semibold rounded-lg text-zinc-600 dark:text-zinc-400 hover:bg-gray-100 dark:hover:bg-zinc-800"
              >
                <ArrowLeft className="h-4 w-4" />
                <span>{t('wizard.prev')}</span>
              </button>
            ) : (
              <div />
            )}

            {currentStep < 6 ? (
              <button
                type="button"
                onClick={nextStep}
                className="inline-flex items-center space-x-1 px-5 py-2 text-xs font-semibold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 transition"
              >
                <span>{t('wizard.next')}</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={handleFinish}
                className="inline-flex items-center space-x-1.5 px-6 py-2 text-xs font-bold rounded-lg bg-emerald-600 text-white hover:bg-emerald-700 shadow-md shadow-emerald-600/30 transition"
              >
                <span>{t('wizard.go_to_dashboard')}</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
