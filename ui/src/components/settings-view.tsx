import type { DynamicConfig } from "@/lib/api"

/** Dynamic settings as formatted JSON, read-only. */
export function SettingsView({ config }: { config: DynamicConfig }) {
  return (
    <pre className="overflow-x-auto rounded-lg border bg-muted/50 p-4 font-mono text-sm">
      {JSON.stringify(config, null, 2)}
    </pre>
  )
}
