import { getToken, setToken } from "@/lib/auth"

/** Where the dynamic settings come from. */
export type ConfigSource = "db" | "file"

/** Who saved a version. */
export type ChangeSource = "api" | "ui" | "cli" | "file"

/** A problem with one setting. */
export interface Issue {
  path: string
  message: string
}

/** Answer of `GET /api/v1/status`. */
export interface Status {
  version: string
  instance: string
  uptime_seconds: number
  config: { source: ConfigSource; version: number | null }
  snapshot: number
  listeners: { name: string; protocol: string; addresses: string[] }[]
}

/** Dynamic settings, shown as they are. */
export type DynamicConfig = Record<string, unknown>

/** Answer of `GET /api/v1/config`. */
export interface ConfigInEffect {
  source: ConfigSource
  version: number | null
  config: DynamicConfig
}

/** A saved version without its settings. */
export interface SavedVersion {
  id: number
  created_at: string
  source: ChangeSource
  comment: string
}

/** A saved version with its settings. */
export interface VersionDetail extends SavedVersion {
  config: DynamicConfig
}

/** Outcome of a change. */
export interface ChangeResult {
  version: number | null
  changed: boolean
}

/** A JSON value. */
export type Json = string | number | boolean | null | Json[] | JsonObject

/** A JSON object. */
export interface JsonObject {
  [key: string]: Json
}

/** The tables of the dynamic settings that the API changes one entity at a time. */
export type Table =
  | "listeners"
  | "routes"
  | "upstreams"
  | "certificates"
  | "consumers"
  | "jwt"

/** A value with its entity tag, which a change sends back to guard against overwriting. */
export interface Tagged<T> {
  value: T
  etag: string | null
}

/** Answer of `POST /api/v1/consumers/{name}/api-keys`: the key, shown this once. */
export interface NewApiKey extends ChangeResult {
  key: string
  hash: string
}

/** The requests of one period: durations in seconds, null without requests. */
export interface Period {
  requests: number
  errors: number
  p50: number | null
  p99: number | null
}

/** The requests of the last full seconds, one entry per second, the oldest first. */
export interface Series {
  /** Name of the route or the upstream; absent for all requests. */
  name?: string
  requests: number[]
  errors: number[]
  p50: (number | null)[]
  p99: (number | null)[]
  /** All the seconds together. */
  summary: Period
}

/** Answer of `GET /api/v1/stats`. */
export interface Stats {
  /** When the last of the seconds ended. */
  until: string
  all: Series
  routes: Series[]
  upstreams: Series[]
}

/** How a target of an upstream is doing. */
export interface TargetHealth {
  address: string
  host: string | null
  weight: number
  state: "healthy" | "unhealthy" | "ejected"
  since: string | null
  until: string | null
  reason: string | null
}

/** Answer of `GET /api/v1/status/upstreams`. */
export interface UpstreamsHealth {
  upstreams: {
    name: string
    health_check: "http" | "tcp" | null
    passive: boolean
    targets: TargetHealth[]
  }[]
}

/** A certificate of the configuration, the one presented and how ACME is doing with it. */
export interface CertificateStatus {
  name: string
  source: "files" | "acme"
  current: {
    names: string[]
    issuer: string
    not_before: string
    not_after: string
  } | null
  acme: {
    renew_at: string | null
    retry_at: string | null
    ordering: boolean
    failures: number
    last_error: string | null
  } | null
}

/** Number of versions loaded at a time. */
export const PAGE_SIZE = 20

/** An error answered by the Admin API. */
export class ApiError extends Error {
  /** HTTP status. */
  readonly status: number
  /** Machine-readable code, such as `invalid_config`. */
  readonly code: string
  /** Problems with single settings. */
  readonly details: Issue[]

  /** Creates the error from the parts of the answer. */
  constructor(status: number, code: string, message: string, details: Issue[]) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
    this.details = details
  }
}

/** JSON shape of an error answer. */
interface ErrorBody {
  error?: { code?: string; message?: string; details?: Issue[] }
}

/**
 * Calls the Admin API with `token`, the stored one by default, and returns the JSON answer.
 * When the stored token is refused it is removed, which leads back to the sign-in page.
 */
async function request<T>(
  path: string,
  init: RequestInit = {},
  token = getToken()
): Promise<T> {
  return (await send<T>(path, init, token)).value
}

/** Calls the Admin API like `request`, and returns the answer with its entity tag. */
function tagged<T>(path: string, init: RequestInit = {}): Promise<Tagged<T>> {
  return send<T>(path, init, getToken())
}

/** Headers of a change that guards against overwriting: the entity must still have `etag`, or
 * must not exist yet without one. */
function conditions(etag: string | null): Record<string, string> {
  return etag === null ? { "If-None-Match": "*" } : { "If-Match": etag }
}

/** Options of a request with `value` as its JSON body. */
function json(method: string, value: Json, headers = {}): RequestInit {
  return {
    method,
    headers: { ...headers, "Content-Type": "application/json" },
    body: JSON.stringify(value),
  }
}

/** Sends a request to the Admin API and reads the JSON answer and its entity tag. */
async function send<T>(
  path: string,
  init: RequestInit,
  token: string | null
): Promise<Tagged<T>> {
  const headers = new Headers(init.headers)
  // Versions saved from here are marked as changes made in the dashboard.
  headers.set("Wormway-Client", "ui")
  if (token !== null) {
    headers.set("Authorization", `Bearer ${token}`)
  }
  const response = await fetch(`/api/v1${path}`, { ...init, headers })
  const body: unknown = await response.json().catch(() => null)
  if (!response.ok) {
    if (response.status === 401 && token !== null && token === getToken()) {
      setToken(null)
    }
    const error = (body as ErrorBody | null)?.error
    throw new ApiError(
      response.status,
      error?.code ?? "http_error",
      error?.message ?? response.statusText,
      error?.details ?? []
    )
  }
  return { value: body as T, etag: response.headers.get("ETag") }
}

/** The endpoints of the Admin API the dashboard uses. */
export const api = {
  /** Status of Wormway; with `token`, checks that token instead of the stored one. */
  status: (token?: string) => request<Status>("/status", {}, token),

  /** The dynamic settings in effect. */
  config: () => request<ConfigInEffect>("/config"),

  /** A page of saved versions, newest first, older than `before` if given. */
  versions: (before?: number) => {
    const older = before === undefined ? "" : `&before=${before}`
    return request<{ versions: SavedVersion[] }>(
      `/config/versions?limit=${PAGE_SIZE}${older}`
    )
  },

  /** One saved version with its settings. */
  version: (id: number) => request<VersionDetail>(`/config/versions/${id}`),

  /** Rolls back to version `id`, unless the version in effect is no longer `current`. */
  rollback: (id: number, current: number | null) =>
    request<ChangeResult>(`/config/versions/${id}/rollback`, {
      method: "POST",
      headers: current === null ? {} : { "If-Match": `"${current}"` },
    }),

  /** Every entity of `table`, by name. */
  entities: async (table: Table) => {
    const body = await request<Record<string, Record<string, JsonObject>>>(
      `/${table}`
    )
    return body[table] ?? {}
  },

  /** Entity `name` of `table`, with its entity tag. */
  entity: (table: Table, name: string) =>
    tagged<JsonObject>(`/${table}/${name}`),

  /** Saves entity `name` of `table`: replaces it if it still has `etag`, or creates it
   * without one if it does not exist. Answers with the entity tag it has now. */
  saveEntity: (
    table: Table,
    name: string,
    value: JsonObject,
    etag: string | null
  ) =>
    tagged<ChangeResult>(
      `/${table}/${name}`,
      json("PUT", value, conditions(etag))
    ),

  /** Removes entity `name` of `table`, if it still has `etag`. */
  deleteEntity: (table: Table, name: string, etag: string | null) =>
    request<ChangeResult>(`/${table}/${name}`, {
      method: "DELETE",
      headers: etag === null ? {} : { "If-Match": etag },
    }),

  /** Sets the password of consumer `name`, if it still has `etag`. */
  setPassword: (name: string, password: string, etag: string) =>
    tagged<ChangeResult>(
      `/consumers/${name}/password`,
      json("PUT", { password }, { "If-Match": etag })
    ),

  /** The requests of the last minute, by second. */
  stats: () => request<Stats>("/stats"),

  /** The upstreams in effect and the health of their targets. */
  health: () => request<UpstreamsHealth>("/status/upstreams"),

  /** The certificates of the configuration in effect and how they are doing. */
  certificates: () =>
    request<{ certificates: CertificateStatus[] }>("/status/certificates"),

  /** Orders certificate `name` again through ACME, now. */
  renew: (name: string) =>
    request<{ requested: boolean }>(`/certificates/${name}/renew`, {
      method: "POST",
    }),

  /** Makes a new API key for consumer `name`, if it still has `etag`. */
  addApiKey: (name: string, etag: string) =>
    tagged<NewApiKey>(`/consumers/${name}/api-keys`, {
      method: "POST",
      headers: { "If-Match": etag },
    }),
}
