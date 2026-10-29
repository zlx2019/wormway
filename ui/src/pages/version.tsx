import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeftIcon, CheckIcon, InfoIcon, RotateCcwIcon } from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useParams } from "react-router"

import { ErrorAlert } from "@/components/error-alert"
import { PageHeader } from "@/components/page-header"
import { SettingsView } from "@/components/settings-view"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { ApiError, api } from "@/lib/api"
import { formatTime } from "@/lib/format"
import { useStatus } from "@/lib/queries"

/** One saved version with its settings, and the rollback to it. */
export function VersionPage() {
  const { t, i18n } = useTranslation()
  const queryClient = useQueryClient()
  const id = Number(useParams().id)
  const valid = Number.isSafeInteger(id) && id > 0
  const status = useStatus()
  const version = useQuery({
    queryKey: ["version", id],
    queryFn: () => api.version(id),
    enabled: valid,
  })
  const [confirming, setConfirming] = useState(false)
  const inEffect = status.data?.config.version ?? null
  const rollback = useMutation({
    mutationFn: () => api.rollback(id, inEffect),
    // The status, the configuration and the versions all change.
    onSettled: () => {
      setConfirming(false)
      void queryClient.invalidateQueries()
    },
  })

  const missing =
    !valid ||
    (version.error instanceof ApiError && version.error.status === 404)
  if (missing) {
    return <ErrorAlert error={new Error(t("version.notFound", { id }))} />
  }
  if (version.isPending) {
    return <Skeleton className="h-64" />
  }
  if (version.isError) {
    return <ErrorAlert error={version.error} />
  }

  const { created_at, source, comment, config } = version.data
  const fileMode = status.data?.config.source === "file"
  const canRollBack = status.data !== undefined && !fileMode && inEffect !== id
  const conflict =
    rollback.error instanceof ApiError && rollback.error.status === 412
  const summary = [
    formatTime(created_at, i18n.language),
    t(`source.${source}`),
    comment,
  ]
  return (
    <>
      <Link
        to="/versions"
        className="mb-4 inline-flex items-center gap-1 text-muted-foreground text-sm hover:text-foreground"
      >
        <ArrowLeftIcon className="size-4" />
        {t("version.back")}
      </Link>
      <PageHeader
        title={t("version.title", { id })}
        description={summary.filter(Boolean).join(" · ")}
      >
        {canRollBack && (
          <Button variant="outline" onClick={() => setConfirming(true)}>
            <RotateCcwIcon />
            {t("version.rollback")}
          </Button>
        )}
      </PageHeader>
      {fileMode && (
        <Alert className="mb-4">
          <InfoIcon />
          <AlertDescription>{t("versions.fileMode")}</AlertDescription>
        </Alert>
      )}
      {rollback.isSuccess && (
        <Alert className="mb-4">
          <CheckIcon />
          <AlertDescription>
            {rollback.data.changed
              ? t("version.rolledBack", { version: rollback.data.version })
              : t("version.unchanged")}
          </AlertDescription>
        </Alert>
      )}
      {rollback.isError && (
        <ErrorAlert
          error={rollback.error}
          message={conflict ? t("version.conflict") : undefined}
        />
      )}
      <SettingsView config={config} />
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("version.confirmTitle", { id })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("version.confirmText", { id })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("version.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              disabled={rollback.isPending}
              onClick={() => rollback.mutate()}
            >
              {t("version.confirm")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
