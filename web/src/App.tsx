import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import { ThemeProvider } from './context/ThemeContext';
import { AppLayout } from './components/layout/AppLayout';
import { DashboardView } from './views/DashboardView';
import { QueryLogView } from './views/QueryLogView';
import { FilteringView } from './views/FilteringView';
import { ClientsView } from './views/ClientsView';
import { RewritesView } from './views/RewritesView';
import { UpstreamsView } from './views/UpstreamsView';
import { SettingsView } from './views/SettingsView';
import { SystemView } from './views/SystemView';
import { WizardView } from './views/WizardView';
import { LoginView } from './views/LoginView';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchOnWindowFocus: false,
      retry: 1,
    },
  },
});

export const App: React.FC = () => {
  return (
    <MantineProvider defaultColorScheme="auto">
      <Notifications position="top-right" zIndex={1000} />
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            <Routes>
              {/* Standalone Views */}
              <Route path="/login" element={<LoginView />} />
              <Route path="/wizard" element={<WizardView />} />

              {/* Main App Layout */}
              <Route path="/" element={<AppLayout />}>
                <Route index element={<DashboardView />} />
                <Route path="querylog" element={<QueryLogView />} />
                <Route path="filtering" element={<FilteringView />} />
                <Route path="clients" element={<ClientsView />} />
                <Route path="rewrites" element={<RewritesView />} />
                <Route path="upstreams" element={<UpstreamsView />} />
                <Route path="settings" element={<SettingsView />} />
                <Route path="system" element={<SystemView />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </BrowserRouter>
        </QueryClientProvider>
      </ThemeProvider>
    </MantineProvider>
  );
};

export default App;
