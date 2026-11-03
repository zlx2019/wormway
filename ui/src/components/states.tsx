import { useTranslation } from "react-i18next"

import { State } from "@/components/charts"
import type { CertificateStatus, TargetHealth } from "@/lib/api"
import { daysUntil, formatTime } from "@/lib/format"

/** Days before the end of its validity from which a certificate is shown as expiring. */
export const EXPIRING_DAYS = 14

/** Whether a target gets no requests now. */
export function isDown(target: TargetHealth): boolean {
  return target.state !== "healthy"
}

/** Whether a certificate needs a look: none presented yet, expiring, expired, or failing to be
 * ordered. */
export function isTroubled(certificate: CertificateStatus): boolean {
  return (
    certificate.current === null ||
    daysUntil(certificate.current.not_after) < EXPIRING_DAYS ||
    (certificate.acme?.failures ?? 0) > 0
  )
}

/** A target of an upstream with its state; the reason and the times show on hover. */
export function TargetState({ target }: { target: TargetHealth }) {
  const { t, i18n } = useTranslation()
  const level =
    target.state === "healthy"
      ? "good"
      : target.state === "ejected"
        ? "serious"
        : "critical"
  const details = [
    t(`health.${target.state}`),
    target.reason,
    target.since &&
      t("health.since", { time: formatTime(target.since, i18n.language) }),
    target.until &&
      t("health.until", { time: formatTime(target.until, i18n.language) }),
  ]
  return (
    <State level={level} title={details.filter(Boolean).join(" · ")}>
      <span className="font-mono text-xs">{target.address}</span>
      <span className="text-muted-foreground text-xs">
        {t(`health.${target.state}`)}
      </span>
    </State>
  )
}

/** When the certificate presented expires, or that none is presented yet. */
export function CertificateExpiry({
  certificate,
}: {
  certificate: CertificateStatus
}) {
  const { t, i18n } = useTranslation()
  if (certificate.current === null) {
    return <State level="warning">{t("certificates.none")}</State>
  }
  const days = daysUntil(certificate.current.not_after)
  const level =
    days < 0 ? "critical" : days < EXPIRING_DAYS ? "warning" : "good"
  const until = formatTime(certificate.current.not_after, i18n.language)
  return (
    <State level={level} title={until}>
      {days < 0
        ? t("certificates.expired")
        : t("certificates.daysLeft", { count: days })}
    </State>
  )
}

/** How ACME is doing with a certificate: ordering, failing, or when it renews. */
export function AcmeProgress({
  certificate,
}: {
  certificate: CertificateStatus
}) {
  const { t, i18n } = useTranslation()
  const acme = certificate.acme
  if (certificate.source !== "acme") {
    return <span className="text-muted-foreground">—</span>
  }
  if (acme === null) {
    return (
      <span className="text-muted-foreground">{t("certificates.waiting")}</span>
    )
  }
  if (acme.ordering) {
    return <span>{t("certificates.ordering")}</span>
  }
  if (acme.failures > 0) {
    const retry =
      acme.retry_at === null ? "" : formatTime(acme.retry_at, i18n.language)
    return (
      <State level="serious" title={acme.last_error ?? undefined}>
        {t("certificates.failing", { count: acme.failures, time: retry })}
      </State>
    )
  }
  return (
    <span>
      {acme.renew_at === null
        ? t("certificates.waiting")
        : t("certificates.renewsAt", {
            time: formatTime(acme.renew_at, i18n.language),
          })}
    </span>
  )
}
