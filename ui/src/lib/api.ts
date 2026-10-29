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
  const headers = new Headers(init.headers)
  // Versions saved from here are marked as changes made in the dashboard.
  headers.set("Zora-Client", "ui")
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
  return body as T
}

/** The endpoints of the Admin API the dashboard uses. */
export const api = {
  /** Status of zora; with `token`, checks that token instead of the stored one. */
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
}
