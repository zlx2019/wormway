import i18n from "i18next"
import { initReactI18next } from "react-i18next"

import { en } from "@/locales/en"
import { zh } from "@/locales/zh"

/** Languages of the dashboard. */
export type Language = "en" | "zh"

/** Key of the chosen language in localStorage. */
const LANGUAGE_KEY = "zora.language"

/** The chosen language; before a choice, Chinese for Chinese browsers and English otherwise. */
function initialLanguage(): Language {
  const saved = localStorage.getItem(LANGUAGE_KEY)
  if (saved === "en" || saved === "zh") {
    return saved
  }
  return navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en"
}

/** Marks the page with `language`, for screen readers and fonts. */
function markPage(language: string): void {
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en"
}

i18n.on("languageChanged", markPage)
void i18n.use(initReactI18next).init({
  resources: { en: { translation: en }, zh: { translation: zh } },
  lng: initialLanguage(),
  fallbackLng: "en",
  // The texts are built in, so there is nothing to wait for.
  initAsync: false,
  // React escapes the texts already.
  interpolation: { escapeValue: false },
})

/** Switches to `language` and remembers the choice. */
export function setLanguage(language: Language): void {
  localStorage.setItem(LANGUAGE_KEY, language)
  void i18n.changeLanguage(language)
}
