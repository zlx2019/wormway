import type { Issue, Json, JsonObject } from "@/lib/api"

/** Whether `value` is a JSON object, not an array or null. */
export function isObject(value: Json | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value)
}

/** Returns the value at `path` in `value`, such as `match.hosts`; undefined if it is not
 * there. */
export function getIn(value: Json | undefined, path: string): Json | undefined {
  let current = value
  for (const key of path.split(".")) {
    if (!isObject(current)) {
      return undefined
    }
    current = current[key]
  }
  return current
}

/**
 * Returns a copy of `value` with `next` at `path`, creating the objects on the way. With
 * undefined the key is removed, so that the setting takes its default.
 */
export function setIn(
  value: JsonObject,
  path: string,
  next: Json | undefined
): JsonObject {
  const [key, ...rest] = path.split(".")
  const copy = { ...value }
  if (rest.length === 0) {
    if (next === undefined) {
      delete copy[key]
    } else {
      copy[key] = next
    }
    return copy
  }
  const inner = copy[key]
  copy[key] = setIn(isObject(inner) ? inner : {}, rest.join("."), next)
  return copy
}

/**
 * Turns the path of a problem with entity `name` of `table`, such as
 * `routes.api.match.paths[0]`, into the path of the setting in the entity: `match.paths.0`.
 * Problems of other settings keep their path.
 */
export function issuePath(issue: Issue, table: string, name: string): string {
  const prefix = `${table}.${name}.`
  const path = issue.path.startsWith(prefix)
    ? issue.path.slice(prefix.length)
    : issue.path
  return path.replace(/\[(\d+)\]/g, ".$1")
}

/** The messages of `issues` about the setting at `path` or inside it. */
export function messagesAt(
  issues: { path: string; message: string }[],
  path: string
): string[] {
  return issues
    .filter((issue) => issue.path === path || issue.path.startsWith(`${path}.`))
    .map((issue) => issue.message)
}

/** Returns a copy of `value` without `keys`. */
export function without(
  value: JsonObject,
  keys: readonly string[]
): JsonObject {
  return Object.fromEntries(
    Object.entries(value).filter(([key]) => !keys.includes(key))
  )
}
