import { LanguagesIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"
import { setLanguage } from "@/i18n"

/** Switches between English and Chinese. */
export function LanguageSwitch() {
  const { t, i18n } = useTranslation()
  return (
    <Button
      variant="ghost"
      size="sm"
      onClick={() => setLanguage(i18n.language === "zh" ? "en" : "zh")}
    >
      <LanguagesIcon />
      {t("app.otherLanguage")}
    </Button>
  )
}
