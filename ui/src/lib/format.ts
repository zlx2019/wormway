import type { TFunction } from "i18next"

/** Formats an uptime in seconds with its two largest units, such as "2d 3h". */
export function formatUptime(seconds: number, t: TFunction): string {
  const parts = [
    ["uptime.days", Math.floor(seconds / 86400)],
    ["uptime.hours", Math.floor(seconds / 3600) % 24],
    ["uptime.minutes", Math.floor(seconds / 60) % 60],
    ["uptime.seconds", seconds % 60],
  ] as const
  const first = parts.findIndex(([, count]) => count > 0)
  // Under a second shows "0s"; otherwise a zero second unit is left out: "1h", not "1h 0m".
  const shown =
    first === -1
      ? parts.slice(3)
      : parts.slice(first, first + 2).filter(([, count]) => count > 0)
  return shown.map(([key, count]) => t(key, { count })).join(" ")
}

/** Formats an RFC 3339 timestamp as local date and time in `language`. */
export function formatTime(timestamp: string, language: string): string {
  return new Date(timestamp).toLocaleString(
    language === "zh" ? "zh-CN" : "en",
    { dateStyle: "medium", timeStyle: "medium" }
  )
}

/** Formats a count, with one decimal at most, in `language`. */
export function formatCount(value: number, language: string): string {
  return value.toLocaleString(language === "zh" ? "zh-CN" : "en", {
    maximumFractionDigits: 1,
  })
}

/** Formats a duration in seconds: milliseconds below a second, seconds from there. */
export function formatSeconds(seconds: number): string {
  if (seconds >= 1) {
    return `${seconds.toFixed(2)} s`
  }
  const millis = seconds * 1000
  return `${millis < 10 ? millis.toFixed(1).replace(/\.0$/, "") : Math.round(millis)} ms`
}

/** Formats a share from 0 to 1 as a percentage. */
export function formatShare(share: number): string {
  return `${(share * 100).toFixed(share > 0 && share < 0.1 ? 1 : 0)}%`
}

/** Whole days from now until `timestamp`, an RFC 3339 time; negative once it is past. */
export function daysUntil(timestamp: string): number {
  return Math.floor((Date.parse(timestamp) - Date.now()) / 86_400_000)
}
