import { useQuery } from "@tanstack/react-query"
import { InfoIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { ErrorAlert } from "@/components/error-alert"
import { PageHeader } from "@/components/page-header"
import { SettingsView } from "@/components/settings-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { api } from "@/lib/api"

/** The dynamic settings in effect, read-only. */
export function ConfigPage() {
  const { t } = useTranslation()
  const config = useQuery({ queryKey: ["config"], queryFn: api.config })
  if (config.isPending) {
    return <Skeleton className="h-64" />
  }
  if (config.isError) {
    return <ErrorAlert error={config.error} />
  }

  const { source, version } = config.data
  return (
    <>
      <PageHeader
        title={t("config.title")}
        description={t("config.description")}
      >
        <div className="flex gap-2">
          <Badge variant="secondary">{t(`source.${source}`)}</Badge>
          <Badge variant="outline">
            {version === null
              ? t("config.noVersion")
              : t("config.version", { version })}
          </Badge>
        </div>
      </PageHeader>
      {source === "file" && (
        <Alert className="mb-4">
          <InfoIcon />
          <AlertDescription>{t("config.fileMode")}</AlertDescription>
        </Alert>
      )}
      <SettingsView config={config.data.config} />
    </>
  )
}
