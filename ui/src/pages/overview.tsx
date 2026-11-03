import { useTranslation } from "react-i18next"
import { Link } from "react-router"

import { LineChart, Sparkline, State } from "@/components/charts"
import { ErrorAlert } from "@/components/error-alert"
import { PageHeader } from "@/components/page-header"
import { isDown, isTroubled } from "@/components/states"
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
import { ApiError, type Series } from "@/lib/api"
import {
  formatCount,
  formatSeconds,
  formatShare,
  formatUptime,
} from "@/lib/format"
import { useCertificates, useHealth, useStats, useStatus } from "@/lib/queries"

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
      <Warnings />
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
      <Traffic />
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

/** What needs a look: targets that get no requests, and certificates that expire soon, are
 * missing or fail to be ordered. Nothing when all is well. */
function Warnings() {
  const { t } = useTranslation()
  const health = useHealth()
  const certificates = useCertificates()
  const down =
    health.data?.upstreams.flatMap((upstream) =>
      upstream.targets.filter(isDown)
    ).length ?? 0
  const troubled =
    certificates.data?.certificates.filter(isTroubled).length ?? 0
  if (down === 0 && troubled === 0) {
    return null
  }
  return (
    <div className="mb-6 flex flex-col gap-2 rounded-xl border p-4 text-sm">
      {down > 0 && (
        <State level="critical">
          <Link to="/upstreams" className="hover:underline">
            {t("overview.targetsDown", { count: down })}
          </Link>
        </State>
      )}
      {troubled > 0 && (
        <State level="warning">
          <Link to="/certificates" className="hover:underline">
            {t("overview.certificatesTroubled", { count: troubled })}
          </Link>
        </State>
      )}
    </div>
  )
}

/** The traffic of the last minute: all requests in figures and charts, then by route and by
 * upstream. Nothing when no service counts the traffic. */
function Traffic() {
  const { t, i18n } = useTranslation()
  const stats = useStats()
  if (stats.isPending) {
    return <Skeleton className="mt-6 h-64" />
  }
  if (stats.isError) {
    const counted = !(
      stats.error instanceof ApiError && stats.error.status === 404
    )
    return counted ? <ErrorAlert error={stats.error} /> : null
  }
  const { all, until } = stats.data
  const { requests, errors, p50, p99 } = all.summary
  const count = (value: number) => formatCount(value, i18n.language)
  return (
    <>
      <Card className="mt-6">
        <CardHeader>
          <CardTitle>{t("overview.traffic")}</CardTitle>
          <CardDescription>{t("overview.trafficHint")}</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <Figure label={t("overview.requests")} value={count(requests)} />
            <Figure
              label={t("overview.errorRate")}
              value={requests === 0 ? "—" : formatShare(errors / requests)}
            />
            <Figure
              label="p50"
              value={p50 === null ? "—" : formatSeconds(p50)}
            />
            <Figure
              label="p99"
              value={p99 === null ? "—" : formatSeconds(p99)}
            />
          </div>
          <div className="grid gap-6 lg:grid-cols-2">
            <div>
              <h3 className="mb-2 font-medium text-sm">
                {t("overview.perSecond")}
              </h3>
              <LineChart
                label={t("overview.perSecond")}
                until={until}
                format={count}
                lines={[
                  {
                    label: t("overview.requests"),
                    values: all.requests,
                    color: "chart-1",
                  },
                  {
                    label: t("overview.errors"),
                    values: all.errors,
                    color: "chart-2",
                  },
                ]}
              />
            </div>
            <div>
              <h3 className="mb-2 font-medium text-sm">
                {t("overview.latency")}
              </h3>
              <LineChart
                label={t("overview.latency")}
                until={until}
                format={formatSeconds}
                lines={[
                  { label: "p50", values: all.p50, color: "chart-1" },
                  { label: "p99", values: all.p99, color: "chart-2" },
                ]}
              />
            </div>
          </div>
        </CardContent>
      </Card>
      <SeriesTable title={t("overview.byRoute")} series={stats.data.routes} />
      <SeriesTable
        title={t("overview.byUpstream")}
        series={stats.data.upstreams}
      />
    </>
  )
}

/** The requests of the last minute of each route or upstream with any, the busiest first. */
function SeriesTable({ title, series }: { title: string; series: Series[] }) {
  const { t, i18n } = useTranslation()
  const busy = series
    .filter((one) => one.summary.requests > 0)
    .sort((a, b) => b.summary.requests - a.summary.requests)
  const quiet = series.length - busy.length
  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {quiet > 0 && (
          <CardDescription>
            {t("overview.quiet", { count: quiet })}
          </CardDescription>
        )}
      </CardHeader>
      {busy.length > 0 && (
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("overview.name")}</TableHead>
                <TableHead className="text-right">
                  {t("overview.requests")}
                </TableHead>
                <TableHead className="text-right">
                  {t("overview.errorRate")}
                </TableHead>
                <TableHead className="text-right">p50</TableHead>
                <TableHead className="text-right">p99</TableHead>
                <TableHead>{t("overview.lastMinute")}</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {busy.map((one) => {
                const { requests, errors, p50, p99 } = one.summary
                return (
                  <TableRow key={one.name}>
                    <TableCell className="font-medium">{one.name}</TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatCount(requests, i18n.language)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {formatShare(errors / requests)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {p50 === null ? "—" : formatSeconds(p50)}
                    </TableCell>
                    <TableCell className="text-right tabular-nums">
                      {p99 === null ? "—" : formatSeconds(p99)}
                    </TableCell>
                    <TableCell>
                      <Sparkline
                        values={one.requests}
                        label={t("overview.sparkline", { name: one.name })}
                      />
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </CardContent>
      )}
    </Card>
  )
}
