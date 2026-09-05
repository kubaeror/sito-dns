import { describe, it, expect } from 'vitest';
import en from '../i18n/locales/en.json';
import pl from '../i18n/locales/pl.json';

describe('i18n completeness', () => {
  const requiredSections = [
    'common',
    'nav',
    'auth',
    'dashboard',
    'querylog',
    'filtering',
    'clients',
    'rewrites',
    'upstreams',
    'settings',
    'system',
    'wizard',
  ];

  it('contains all required top-level sections in EN', () => {
    for (const section of requiredSections) {
      expect(en).toHaveProperty(section);
      expect(typeof (en as Record<string, unknown>)[section]).toBe('object');
    }
  });

  it('contains all required top-level sections in PL', () => {
    for (const section of requiredSections) {
      expect(pl).toHaveProperty(section);
      expect(typeof (pl as Record<string, unknown>)[section]).toBe('object');
    }
  });

  it('has identical keys in common between EN and PL', () => {
    const enCommon = Object.keys(en.common).sort();
    const plCommon = Object.keys(pl.common).sort();
    expect(plCommon).toEqual(enCommon);
  });

  it('has identical keys in nav between EN and PL', () => {
    const enNav = Object.keys(en.nav).sort();
    const plNav = Object.keys(pl.nav).sort();
    expect(plNav).toEqual(enNav);
  });

  it('has identical keys in auth between EN and PL', () => {
    const enAuth = Object.keys(en.auth).sort();
    const plAuth = Object.keys(pl.auth).sort();
    expect(plAuth).toEqual(enAuth);
  });

  it('has identical keys in dashboard between EN and PL', () => {
    const enDash = Object.keys(en.dashboard).sort();
    const plDash = Object.keys(pl.dashboard).sort();
    expect(plDash).toEqual(enDash);
  });

  it('has identical keys in querylog between EN and PL', () => {
    const enQ = Object.keys(en.querylog).sort();
    const plQ = Object.keys(pl.querylog).sort();
    expect(plQ).toEqual(enQ);
  });

  it('has identical keys in wizard between EN and PL', () => {
    const enW = Object.keys(en.wizard).sort();
    const plW = Object.keys(pl.wizard).sort();
    expect(plW).toEqual(enW);
  });
});
