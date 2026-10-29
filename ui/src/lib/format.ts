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
