import type { TFunction } from "i18next"
import { useTranslation } from "react-i18next"

import { EntityList, type Kind } from "@/components/entity"
import { CertificateForm } from "@/forms/certificate"
import { JwtForm } from "@/forms/jwt"
import { ListenerForm } from "@/forms/listener"
import { RouteForm } from "@/forms/route"
import { UpstreamForm } from "@/forms/upstream"
import type { Json, JsonObject } from "@/lib/api"
import { getIn, isObject } from "@/lib/draft"

/** The routes, edited with their form. */
export const routes: Kind = {
  table: "routes",
  path: "/routes",
  Form: RouteForm,
  fresh: {},
}

/** The upstreams, edited with their form. */
export const upstreams: Kind = {
  table: "upstreams",
  path: "/upstreams",
  Form: UpstreamForm,
  fresh: { targets: [] },
}

/** The listeners, edited with their form. */
export const listeners: Kind = {
  table: "listeners",
  path: "/listeners",
  Form: ListenerForm,
  fresh: { listen: [], protocol: "http" },
}

/** The certificates, edited with their form. */
export const certificates: Kind = {
  table: "certificates",
  path: "/certificates",
  Form: CertificateForm,
  fresh: {},
}

/** The settings that check JWTs, edited with their form. */
export const jwt: Kind = {
  table: "jwt",
  path: "/jwt",
  Form: JwtForm,
  fresh: { algorithm: "HS256", secret: { env: "JWT_SECRET" } },
}

/** Shows a list setting as its items separated by commas; a dash when it is empty. */
export function items(value: Json | undefined): string {
  if (Array.isArray(value) && value.length > 0) {
    return value.map((item) => (isObject(item) ? "…" : String(item))).join(", ")
  }
  return "—"
}

/** Shows the path conditions of `route`: `/a` for a prefix, `= /a` for an exact path and
 * `~ re` for a regular expression. */
function paths(route: JsonObject): string {
  const patterns = getIn(route, "match.paths")
  if (!Array.isArray(patterns) || patterns.length === 0) {
    return "—"
  }
  return patterns
    .map((pattern) => {
      if (!isObject(pattern)) {
        return String(pattern)
      }
      return "exact" in pattern
        ? `= ${String(pattern.exact)}`
        : `~ ${String(pattern.regex)}`
    })
    .join(", ")
}

/** Shows what `route` does: the upstream it passes requests to, where it redirects them, or
 * the status it answers with. */
function action(route: JsonObject, t: TFunction): string {
  if (isObject(route.redirect)) {
    return `${t("routes.redirect")} ${String(route.redirect.to)}`
  }
  if (isObject(route.respond)) {
    return `${t("routes.respond")} ${String(route.respond.status)}`
  }
  return typeof route.upstream === "string" ? `→ ${route.upstream}` : "—"
}

/** Shows the ways in which `route` takes credentials. */
function auth(route: JsonObject, t: TFunction): string {
  if (!isObject(route.auth)) {
    return "—"
  }
  const ways = [
    route.auth.basic === true && "Basic",
    route.auth.api_key !== undefined &&
      route.auth.api_key !== false &&
      t("routes.apiKey"),
    typeof route.auth.jwt === "string" && `JWT ${route.auth.jwt}`,
  ]
  return ways.filter(Boolean).join(", ")
}

/** The routes and what each one does. */
export function RoutesPage() {
  const { t } = useTranslation()
  return (
    <EntityList
      table="routes"
      path="/routes"
      title={t("routes.title")}
      description={t("routes.description")}
      columns={[
        {
          title: t("routes.hosts"),
          render: (route) => items(getIn(route, "match.hosts")),
        },
        { title: t("routes.paths"), render: (route) => paths(route) },
        { title: t("routes.action"), render: (route) => action(route, t) },
        { title: t("routes.auth"), render: (route) => auth(route, t) },
      ]}
    />
  )
}

/** The upstreams and their targets. */
export function UpstreamsPage() {
  const { t } = useTranslation()
  return (
    <EntityList
      table="upstreams"
      path="/upstreams"
      title={t("upstreams.title")}
      description={t("upstreams.description")}
      columns={[
        {
          title: t("upstreams.targets"),
          render: (upstream) =>
            Array.isArray(upstream.targets)
              ? upstream.targets
                  .map((target) =>
                    isObject(target) ? String(target.address) : String(target)
                  )
                  .join(", ")
              : "—",
        },
        {
          title: t("upstreams.balance"),
          render: (upstream) =>
            typeof upstream.balance === "string"
              ? upstream.balance
              : "round_robin",
        },
      ]}
    />
  )
}

/** The listeners and their addresses. */
export function ListenersPage() {
  const { t } = useTranslation()
  return (
    <EntityList
      table="listeners"
      path="/listeners"
      title={t("listeners.title")}
      description={t("listeners.description")}
      columns={[
        {
          title: t("listeners.listen"),
          render: (listener) => items(listener.listen),
        },
        {
          title: t("listeners.certificates"),
          render: (listener) => items(getIn(listener, "tls.certificates")),
        },
      ]}
    />
  )
}

/** The certificates and where they come from. */
export function CertificatesPage() {
  const { t } = useTranslation()
  return (
    <EntityList
      table="certificates"
      path="/certificates"
      title={t("certificates.title")}
      description={t("certificates.description")}
      columns={[
        {
          title: t("certificates.source"),
          render: (certificate) =>
            isObject(certificate.acme) ? "ACME" : t("certificates.files"),
        },
        {
          title: t("certificates.covers"),
          render: (certificate) =>
            isObject(certificate.acme)
              ? items(certificate.acme.domains)
              : typeof certificate.cert === "string"
                ? certificate.cert
                : "—",
        },
      ]}
    />
  )
}
