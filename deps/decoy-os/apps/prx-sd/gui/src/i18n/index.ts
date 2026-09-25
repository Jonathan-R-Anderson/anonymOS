import { reactive } from 'vue';

type Lang = 'en' | 'zh' | 'ru' | 'ka' | 'ja' | 'ko' | 'es' | 'fr' | 'de' | 'ar';
const state = reactive({ locale: (localStorage.getItem('locale') || localStorage.getItem('prxsd-lang') || 'en') as Lang });

import en from './en';
import zh from './zh';
import ru from './ru';
import ka from './ka';
import ja from './ja';
import ko from './ko';
import es from './es';
import fr from './fr';
import de from './de';
import ar from './ar';

const messages: Record<Lang, Record<string, string>> = { en, zh, ru, ka, ja, ko, es, fr, de, ar };

export function t(key: string): string {
  return messages[state.locale][key] || messages['en'][key] || key;
}

export function setLocale(lang: Lang) {
  state.locale = lang;
  localStorage.setItem('locale', lang);
}

export function getLocale(): Lang {
  return state.locale;
}

export const locales = [
  { code: 'en', name: 'English' },
  { code: 'zh', name: '中文' },
  { code: 'ja', name: '日本語' },
  { code: 'ko', name: '한국어' },
  { code: 'es', name: 'Español' },
  { code: 'fr', name: 'Français' },
  { code: 'de', name: 'Deutsch' },
  { code: 'ar', name: 'العربية' },
  { code: 'ru', name: 'Русский' },
  { code: 'ka', name: 'ქართული' },
];
