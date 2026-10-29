import { useTranslation } from "react-i18next"

import { ErrorAlert } from "@/components/error-alert"
import { PageHeader } from "@/components/page-header"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { formatUptime } from "@/lib/format"
import { useStatus } from "@/lib/queries"

/** Overview: version, uptime, configuration and listeners, kept up to date. */
export function OverviewPage() {
  const { t } = useTranslation()
  const status = useStatus()
  if (status.isPending) {
    return <Skeleton className="h-64" />
  }
  if (status.isError) {
    return <ErrorAlert error={status.error} />
  }

  const { config, listeners } = status.data
  const source = t(`source.${config.source}`)
  return (
    <>
      <PageHeader title={t("overview.title")} />
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Figure label={t("overview.version")} value={status.data.version} />
        <Figure
          label={t("overview.uptime")}
          value={formatUptime(status.data.uptime_seconds, t)}
        />
        <Figure
          label={t("overview.config")}
          value={
            config.version === null
              ? t("overview.configNoVersion", { source })
              : t("overview.configVersion", {
                  source,
                  version: config.version,
                })
          }
        />
        <Figure
          label={t("overview.snapshot")}
          value={String(status.data.snapshot)}
        />
      </div>
      <Card className="mt-6">
        <CardHeader>
          <CardTitle>{t("overview.listeners")}</CardTitle>
        </CardHeader>
        <CardContent>
          {listeners.length === 0 ? (
            <p className="text-muted-foreground">{t("overview.noListeners")}</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("overview.name")}</TableHead>
                  <TableHead>{t("overview.protocol")}</TableHead>
                  <TableHead>{t("overview.addresses")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listeners.map((listener) => (
                  <TableRow key={listener.name}>
                    <TableCell className="font-medium">
                      {listener.name}
                    </TableCell>
                    <TableCell>{listener.protocol}</TableCell>
                    <TableCell className="font-mono">
                      {listener.addresses.join(", ")}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
      <p className="mt-6 text-muted-foreground text-xs">
        {t("overview.instance", { id: status.data.instance })}
      </p>
    </>
  )
}

/** One figure of the overview. */
function Figure({ label, value }: { label: string; value: string }) {
  return (
    <Card size="sm">
      <CardHeader>
        <CardDescription>{label}</CardDescription>
        <CardTitle className="text-lg">{value}</CardTitle>
      </CardHeader>
    </Card>
  )
}
