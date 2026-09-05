import { describe, it, expect, beforeAll, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MantineProvider } from '@mantine/core';
import { MemoryRouter } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ThemeProvider } from '../context/ThemeContext';
import { AppLayout } from '../components/layout/AppLayout';
import '../i18n';

beforeAll(() => {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
});

describe('AppLayout Component', () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  });

  it('renders application navigation items and brand name', () => {
    render(
      <QueryClientProvider client={queryClient}>
        <MantineProvider>
          <ThemeProvider>
            <MemoryRouter>
              <AppLayout />
            </MemoryRouter>
          </ThemeProvider>
        </MantineProvider>
      </QueryClientProvider>
    );

    expect(screen.getByText('sito')).toBeDefined();
    expect(screen.getByText('Dashboard')).toBeDefined();
    expect(screen.getByText('Query Log')).toBeDefined();
  });
});
