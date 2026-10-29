import { useTranslation } from "react-i18next"
import { Link } from "react-router"

/** Answer for paths the dashboard does not know. */
export function NotFoundPage() {
  const { t } = useTranslation()
  return (
    <div className="py-12 text-center">
      <h1 className="font-semibold text-xl">{t("notFound.title")}</h1>
      <Link
        to="/"
        className="mt-4 inline-block text-sm underline underline-offset-4"
      >
        {t("notFound.back")}
      </Link>
    </div>
  )
}
