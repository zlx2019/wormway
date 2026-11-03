import { cn } from "cn"
import {
  CircleAlertIcon,
  CircleCheckIcon,
  CircleXIcon,
  TriangleAlertIcon,
} from "lucide-react"
import {
  type KeyboardEvent,
  type PointerEvent,
  type ReactNode,
  useState,
} from "react"
import { useTranslation } from "react-i18next"

/** One line of a chart. */
export interface Line {
  /** What it shows, for the legend and the readout. */
  label: string
  /** One value per second, the oldest first; null where there is none. */
  values: (number | null)[]
  /** Its color: the first or the second color of the charts. */
  color: "chart-1" | "chart-2"
}

/** Classes of each color, written out so that Tailwind finds them. */
const STROKES = { "chart-1": "stroke-chart-1", "chart-2": "stroke-chart-2" }
const FILLS = { "chart-1": "bg-chart-1", "chart-2": "bg-chart-2" }

/** Size of the drawing, which stretches to the width of the chart. */
const WIDTH = 600
const HEIGHT = 160

/** Returns the smallest round number at or above `value`: 1, 2 or 5 times a power of ten. */
export function roundUp(value: number): number {
  if (value <= 0) {
    return 1
  }
  const power = 10 ** Math.floor(Math.log10(value))
  return (
    [1, 2, 5, 10].map((step) => step * power).find((top) => value <= top) ??
    10 * power
  )
}

/** Where value `index` of `count` sits across the chart, from 0 to 1. */
function across(index: number, count: number): number {
  return count <= 1 ? 1 : index / (count - 1)
}

/** The runs of `values` without gaps, as SVG points, and the points alone between gaps. */
function shape(
  values: (number | null)[],
  top: number
): { runs: string[]; dots: [number, number][] } {
  const runs: string[] = []
  const dots: [number, number][] = []
  let run: [number, number][] = []
  /** Ends the current run: a line with two points or more, a dot otherwise. */
  const close = () => {
    if (run.length === 1) {
      dots.push(run[0])
    } else if (run.length > 1) {
      runs.push(run.map(([x, y]) => `${x * WIDTH},${y * HEIGHT}`).join(" "))
    }
    run = []
  }
  values.forEach((value, index) => {
    if (value === null) {
      close()
    } else {
      run.push([across(index, values.length), 1 - value / top])
    }
  })
  close()
  return { runs, dots }
}

/**
 * Lines over the seconds that ended at `until`, on one axis from zero, with a legend for two
 * lines or more. Pointing at the chart, or moving through it with the arrow keys, shows the
 * values of every line at that second; `format` writes them.
 */
export function LineChart({
  label,
  lines,
  until,
  format,
}: {
  label: string
  lines: Line[]
  until: string
  format: (value: number) => string
}) {
  const { t, i18n } = useTranslation()
  const [at, setAt] = useState<number | null>(null)
  const count = Math.max(0, ...lines.map((line) => line.values.length))
  const values = lines.flatMap((line) =>
    line.values.filter((value): value is number => value !== null)
  )
  const top = roundUp(Math.max(0, ...values))
  const end = Date.parse(until)

  /** Follows the pointer to the nearest second. */
  function point(event: PointerEvent<HTMLDivElement>) {
    const box = event.currentTarget.getBoundingClientRect()
    const index = Math.round(
      ((event.clientX - box.left) / box.width) * (count - 1)
    )
    setAt(Math.min(count - 1, Math.max(0, index)))
  }
  /** Moves through the seconds with the arrow keys. */
  function step(event: KeyboardEvent<HTMLDivElement>) {
    const moves: Record<string, number> = { ArrowLeft: -1, ArrowRight: 1 }
    if (event.key in moves) {
      event.preventDefault()
      setAt((current) =>
        Math.min(
          count - 1,
          Math.max(0, (current ?? count - 1) + moves[event.key])
        )
      )
    } else if (event.key === "Escape") {
      setAt(null)
    }
  }

  const time =
    at === null
      ? ""
      : new Date(end - (count - 1 - at) * 1000).toLocaleTimeString(
          i18n.language === "zh" ? "zh-CN" : "en"
        )
  return (
    <figure className="flex flex-col gap-2">
      {lines.length > 1 && (
        <figcaption className="flex flex-wrap gap-x-4 gap-y-1 text-muted-foreground text-xs">
          {lines.map((line) => (
            <span key={line.label} className="inline-flex items-center gap-1.5">
              <span
                className={cn("h-0.5 w-3 rounded-full", FILLS[line.color])}
              />
              {line.label}
            </span>
          ))}
        </figcaption>
      )}
      <div className="flex gap-2">
        <div className="flex h-40 flex-col justify-between text-right text-muted-foreground text-xs tabular-nums">
          <span>{format(top)}</span>
          <span>{format(top / 2)}</span>
          <span>{format(0)}</span>
        </div>
        <div
          role="img"
          aria-label={label}
          // biome-ignore lint/a11y/noNoninteractiveTabindex: the arrow keys move the readout
          tabIndex={0}
          className="relative h-40 flex-1 rounded-sm outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
          onPointerMove={point}
          onPointerLeave={() => setAt(null)}
          onFocus={() => setAt(count - 1)}
          onBlur={() => setAt(null)}
          onKeyDown={step}
        >
          <svg
            viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
            preserveAspectRatio="none"
            className="absolute inset-0 size-full overflow-visible"
            aria-hidden="true"
          >
            {[0, 0.5, 1].map((level) => (
              <line
                key={level}
                x1={0}
                x2={WIDTH}
                y1={level * HEIGHT}
                y2={level * HEIGHT}
                className="stroke-border"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
            ))}
            {lines.flatMap((line) =>
              shape(line.values, top).runs.map((points) => (
                <polyline
                  key={`${line.label} ${points}`}
                  points={points}
                  className={cn("fill-none", STROKES[line.color])}
                  strokeWidth={2}
                  strokeLinejoin="round"
                  strokeLinecap="round"
                  vectorEffect="non-scaling-stroke"
                />
              ))
            )}
            {at !== null && (
              <line
                x1={across(at, count) * WIDTH}
                x2={across(at, count) * WIDTH}
                y1={0}
                y2={HEIGHT}
                className="stroke-muted-foreground"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
            )}
          </svg>
          {lines.flatMap((line) =>
            shape(line.values, top).dots.map(([x, y]) => (
              <Dot key={`${line.label} ${x}`} x={x} y={y} color={line.color} />
            ))
          )}
          {at !== null &&
            lines.map((line) => {
              const value = line.values[at]
              return value === null || value === undefined ? null : (
                <Dot
                  key={line.label}
                  x={across(at, count)}
                  y={1 - value / top}
                  color={line.color}
                />
              )
            })}
          {at !== null && (
            <div
              className="pointer-events-none absolute top-0 z-10 rounded-md border bg-popover px-2 py-1 text-popover-foreground text-xs shadow-sm"
              style={{
                left: `${across(at, count) * 100}%`,
                transform: `translateX(${across(at, count) > 0.5 ? "calc(-100% - 8px)" : "8px"})`,
              }}
            >
              <div className="mb-1 text-muted-foreground">{time}</div>
              {lines.map((line) => {
                const value = line.values[at]
                return (
                  <div key={line.label} className="flex items-center gap-1.5">
                    <span
                      className={cn(
                        "h-0.5 w-3 rounded-full",
                        FILLS[line.color]
                      )}
                    />
                    <span className="font-medium tabular-nums">
                      {value === null || value === undefined
                        ? "—"
                        : format(value)}
                    </span>
                    <span className="text-muted-foreground">{line.label}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
      <div className="flex justify-between pl-10 text-muted-foreground text-xs">
        <span>{t("charts.ago", { count })}</span>
        <span>{t("charts.now")}</span>
      </div>
    </figure>
  )
}

/** A point of a line, with a ring of the card color so that it stands out where lines cross;
 * `x` and `y` go from 0 to 1 across and down the chart. */
function Dot({ x, y, color }: { x: number; y: number; color: Line["color"] }) {
  return (
    <span
      className={cn(
        "pointer-events-none absolute size-2 -translate-x-1/2 -translate-y-1/2 rounded-full ring-2 ring-card",
        FILLS[color]
      )}
      style={{ left: `${x * 100}%`, top: `${y * 100}%` }}
    />
  )
}

/** The values of a short series as a small line, without axes; `label` reads it out. */
export function Sparkline({
  values,
  label,
}: {
  values: number[]
  label: string
}) {
  const top = Math.max(1, ...values)
  const points = values
    .map(
      (value, index) =>
        `${across(index, values.length) * 120},${(1 - value / top) * 24}`
    )
    .join(" ")
  return (
    <svg
      viewBox="0 0 120 24"
      preserveAspectRatio="none"
      className="h-6 w-28 overflow-visible"
      role="img"
      aria-label={label}
    >
      <polyline
        points={points}
        className="fill-none stroke-chart-1"
        strokeWidth={1.5}
        strokeLinejoin="round"
        strokeLinecap="round"
        vectorEffect="non-scaling-stroke"
      />
    </svg>
  )
}

/** The icon of each state. */
const STATE_ICONS = {
  good: CircleCheckIcon,
  warning: TriangleAlertIcon,
  serious: CircleAlertIcon,
  critical: CircleXIcon,
}

/** The color of each state, written out so that Tailwind finds them. */
const STATE_COLORS = {
  good: "text-good",
  warning: "text-warning",
  serious: "text-serious",
  critical: "text-critical",
}

/** A state shown with its icon and `children` as its words, never by color alone. */
export function State({
  level,
  children,
  title,
}: {
  level: keyof typeof STATE_ICONS
  children: ReactNode
  title?: string
}) {
  const Icon = STATE_ICONS[level]
  return (
    <span className="inline-flex items-center gap-1" title={title}>
      <Icon
        className={cn("size-4 shrink-0", STATE_COLORS[level])}
        aria-hidden="true"
      />
      {children}
    </span>
  )
}
