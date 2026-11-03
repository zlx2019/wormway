import { PlusIcon, Trash2Icon } from "lucide-react"
import { useEffect, useId, useState } from "react"
import { useTranslation } from "react-i18next"

import {
  Choice,
  Group,
  LinesSetting,
  NamesSetting,
  NumberSetting,
  RowsSetting,
  Section,
  SelectSetting,
  SwitchSetting,
  TextSetting,
  useDraft,
  useSetting,
} from "@/components/draft"
import { useNames } from "@/components/entity"
import { Button } from "@/components/ui/button"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import type { Json, JsonObject } from "@/lib/api"
import { isObject, without } from "@/lib/draft"

/** The form of a route. Path rewrites, header changes and time limits are in its JSON. */
export function RouteForm() {
  const { t } = useTranslation()
  const listeners = useNames("listeners")
  const jwt = useNames("jwt")
  return (
    <FieldGroup>
      <NamesSetting
        path="listeners"
        label={t("routes.listeners")}
        hint={t("routes.listenersHint")}
        names={listeners}
      />
      <NumberSetting
        path="priority"
        label={t("routes.priority")}
        hint={t("routes.priorityHint")}
        placeholder="0"
      />
      <Group title={t("routes.match")} hint={t("routes.matchHint")}>
        <LinesSetting
          path="match.hosts"
          label={t("routes.hosts")}
          hint={t("routes.hostsHint")}
          placeholder={"example.com\n*.example.com"}
        />
        <PathsSetting />
        <LinesSetting
          path="match.methods"
          label={t("routes.methods")}
          hint={t("routes.methodsHint")}
          placeholder={"GET\nPOST"}
        />
        <HeadersSetting />
      </Group>
      <ActionSetting />
      <Section
        path="auth"
        title={t("routes.auth")}
        hint={t("routes.authHint")}
        initial={{ api_key: true }}
      >
        <SwitchSetting
          path="auth.basic"
          label={t("routes.basic")}
          hint={t("routes.basicHint")}
        />
        <ApiKeySetting />
        <SelectSetting
          path="auth.jwt"
          label={t("routes.jwt")}
          hint={t("routes.jwtHint")}
          options={jwt.map((name) => ({ value: name, label: name }))}
          fallback={t("routes.noJwt")}
        />
        <LinesSetting
          path="auth.consumers"
          label={t("routes.consumers")}
          hint={t("routes.consumersHint")}
        />
      </Section>
      <Section
        path="rate_limit"
        title={t("routes.rateLimit")}
        hint={t("routes.rateLimitHint")}
        initial={{ requests: 100, per: "1s" }}
      >
        <NumberSetting
          path="rate_limit.requests"
          label={t("routes.requests")}
        />
        <TextSetting
          path="rate_limit.per"
          label={t("routes.per")}
          placeholder="1s"
        />
        <RateKeySetting />
      </Section>
      <Group title={t("routes.limits")}>
        <NumberSetting
          path="concurrency_limit"
          label={t("routes.concurrency")}
          hint={t("routes.concurrencyHint")}
        />
        <TextSetting
          path="max_body_size"
          label={t("routes.maxBody")}
          hint={t("routes.maxBodyHint")}
          placeholder="10MiB"
        />
      </Group>
      <SwitchSetting
        path="compress"
        label={t("routes.compress")}
        hint={t("routes.compressHint")}
      />
      <SwitchSetting
        path="access_log"
        label={t("routes.accessLog")}
        fallback={true}
      />
    </FieldGroup>
  )
}

/** The path conditions: each a prefix, an exact path or a regular expression. */
function PathsSetting() {
  const { t } = useTranslation()
  const kinds = [
    { value: "prefix", label: t("routes.prefix") },
    { value: "exact", label: t("routes.exact") },
    { value: "regex", label: t("routes.regex") },
  ]
  /** A path condition of `kind` for `text`. */
  const make = (kind: string, text: string): Json =>
    kind === "prefix" ? text : { [kind]: text }
  return (
    <RowsSetting
      path="match.paths"
      label={t("routes.paths")}
      hint={t("routes.pathsHint")}
      fresh="/"
      render={(item, change, readOnly) => {
        const kind = isObject(item)
          ? "exact" in item
            ? "exact"
            : "regex"
          : "prefix"
        const text = isObject(item)
          ? String(item.exact ?? item.regex ?? "")
          : String(item)
        return (
          <>
            <NativeSelect
              value={kind}
              className="shrink-0"
              disabled={readOnly}
              aria-label={t("routes.pathKind")}
              onChange={(event) => change(make(event.target.value, text))}
            >
              {kinds.map((option) => (
                <NativeSelectOption key={option.value} value={option.value}>
                  {option.label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <Input
              value={text}
              className="font-mono"
              disabled={readOnly}
              aria-label={t("routes.paths")}
              onChange={(event) => change(make(kind, event.target.value))}
            />
          </>
        )
      }}
    />
  )
}

/** A header condition being edited: the header, and its value, or whether it is there. */
interface HeaderRow {
  name: string
  mode: "equals" | "present" | "absent"
  value: string
}

/** Turns the header conditions of a route into rows. */
function headerRows(conditions: Json | undefined): HeaderRow[] {
  if (!isObject(conditions)) {
    return []
  }
  return Object.entries(conditions).map(([name, condition]) =>
    typeof condition === "string"
      ? { name, mode: "equals", value: condition }
      : { name, mode: condition === false ? "absent" : "present", value: "" }
  )
}

/** Turns rows back into header conditions; rows without a header are left out. */
function headerConditions(rows: HeaderRow[]): JsonObject | undefined {
  const named = rows.filter((row) => row.name !== "")
  if (named.length === 0) {
    return undefined
  }
  return Object.fromEntries(
    named.map((row) => [
      row.name,
      row.mode === "equals" ? row.value : row.mode === "present",
    ])
  )
}

/** The header conditions: a header equal to a value, present, or absent. */
function HeadersSetting() {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting("match.headers")
  const [rows, setRows] = useState(() => headerRows(value))
  const written = JSON.stringify(value ?? null)
  // Takes changes made elsewhere, such as in the JSON tab, unless the rows say the same.
  useEffect(() => {
    setRows((current) =>
      JSON.stringify(headerConditions(current) ?? null) === written
        ? current
        : headerRows(JSON.parse(written) as Json)
    )
  }, [written])
  /** Replaces the rows and the conditions they make. */
  function replace(next: HeaderRow[]) {
    setRows(next)
    set(headerConditions(next))
  }
  const modes = [
    { value: "equals", label: t("routes.headerEquals") },
    { value: "present", label: t("routes.headerPresent") },
    { value: "absent", label: t("routes.headerAbsent") },
  ]
  return (
    <Field data-invalid={messages.length > 0}>
      <FieldLabel htmlFor={id}>{t("routes.headers")}</FieldLabel>
      <div id={id} className="flex flex-col gap-2">
        {rows.map((row, index) => (
          <div
            // biome-ignore lint/suspicious/noArrayIndexKey: rows have no identity but their place
            key={index}
            className="flex items-center gap-2"
          >
            <Input
              value={row.name}
              placeholder="X-Canary"
              className="font-mono"
              disabled={readOnly}
              aria-label={t("routes.headerName")}
              onChange={(event) =>
                replace(
                  rows.map((old, i) =>
                    i === index ? { ...old, name: event.target.value } : old
                  )
                )
              }
            />
            <NativeSelect
              value={row.mode}
              className="shrink-0"
              disabled={readOnly}
              aria-label={t("routes.headerMode")}
              onChange={(event) =>
                replace(
                  rows.map((old, i) =>
                    i === index
                      ? {
                          ...old,
                          mode: event.target.value as HeaderRow["mode"],
                        }
                      : old
                  )
                )
              }
            >
              {modes.map((mode) => (
                <NativeSelectOption key={mode.value} value={mode.value}>
                  {mode.label}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            {row.mode === "equals" && (
              <Input
                value={row.value}
                className="font-mono"
                disabled={readOnly}
                aria-label={t("routes.headerValue")}
                onChange={(event) =>
                  replace(
                    rows.map((old, i) =>
                      i === index ? { ...old, value: event.target.value } : old
                    )
                  )
                }
              />
            )}
            <Button
              variant="ghost"
              size="icon"
              disabled={readOnly}
              aria-label={t("form.remove")}
              onClick={() => replace(rows.filter((_, i) => i !== index))}
            >
              <Trash2Icon />
            </Button>
          </div>
        ))}
        <Button
          variant="outline"
          size="sm"
          className="w-fit"
          disabled={readOnly}
          onClick={() =>
            setRows([...rows, { name: "", mode: "equals", value: "" }])
          }
        >
          <PlusIcon />
          {t("form.add")}
        </Button>
      </div>
      <FieldDescription>{t("routes.headersHint")}</FieldDescription>
      <FieldError errors={messages.map((message) => ({ message }))} />
    </Field>
  )
}

/** What the route does: pass requests on to an upstream, redirect them, or answer them. */
function ActionSetting() {
  const { t } = useTranslation()
  const upstreams = useNames("upstreams")
  const { draft, update } = useDraft()
  const action =
    "redirect" in draft
      ? "redirect"
      : "respond" in draft
        ? "respond"
        : "upstream"
  /** Switches to another action, leaving out the settings of the others. */
  function choose(next: string) {
    update((current) => {
      const rest = without(current, ["upstream", "redirect", "respond"])
      if (next === "redirect") {
        return { ...rest, redirect: { to: "https://{host}{uri}" } }
      }
      if (next === "respond") {
        return { ...rest, respond: { status: 200 } }
      }
      return rest
    })
  }
  return (
    <Group title={t("routes.action")}>
      <Choice
        label={t("routes.actionKind")}
        value={action}
        options={[
          { value: "upstream", label: t("routes.toUpstream") },
          { value: "redirect", label: t("routes.redirect") },
          { value: "respond", label: t("routes.respond") },
        ]}
        onChange={choose}
      />
      {action === "upstream" && (
        <SelectSetting
          path="upstream"
          label={t("routes.upstream")}
          options={upstreams.map((name) => ({ value: name, label: name }))}
          fallback={t("form.choose")}
        />
      )}
      {action === "redirect" && (
        <>
          <TextSetting
            path="redirect.to"
            label={t("routes.redirectTo")}
            hint={t("routes.redirectToHint")}
            placeholder="https://{host}{uri}"
          />
          <NumberSetting
            path="redirect.status"
            label={t("routes.status")}
            placeholder="302"
          />
        </>
      )}
      {action === "respond" && (
        <>
          <NumberSetting path="respond.status" label={t("routes.status")} />
          <TextSetting
            path="respond.body"
            label={t("routes.body")}
            multiline={true}
          />
        </>
      )}
    </Group>
  )
}

/** API keys: on or off, and the header they come in, `X-API-Key` unless set. */
function ApiKeySetting() {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting("auth.api_key")
  const on = value === true || isObject(value)
  const header =
    isObject(value) && typeof value.header === "string" ? value.header : ""
  return (
    <Field data-invalid={messages.length > 0}>
      <div className="flex items-center gap-2">
        <Switch
          id={id}
          checked={on}
          disabled={readOnly}
          onCheckedChange={(next) =>
            set(next ? (header === "" ? true : { header }) : undefined)
          }
        />
        <FieldLabel htmlFor={id}>{t("routes.apiKey")}</FieldLabel>
      </div>
      {on && (
        <Input
          value={header}
          placeholder="X-API-Key"
          className="font-mono"
          disabled={readOnly}
          aria-label={t("routes.apiKeyHeader")}
          onChange={(event) =>
            set(
              event.target.value === "" ? true : { header: event.target.value }
            )
          }
        />
      )}
      <FieldDescription>{t("routes.apiKeyHint")}</FieldDescription>
      <FieldError errors={messages.map((message) => ({ message }))} />
    </Field>
  )
}

/** What the rate limit counts by: the client IP address unless set, a header, the consumer, or
 * the whole route. */
function RateKeySetting() {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting("rate_limit.key")
  const kind = isObject(value)
    ? "header"
    : typeof value === "string"
      ? value
      : "client_ip"
  const header =
    isObject(value) && typeof value.header === "string" ? value.header : ""
  const kinds = [
    { value: "client_ip", label: t("routes.keyClientIp") },
    { value: "header", label: t("routes.keyHeader") },
    { value: "consumer", label: t("routes.keyConsumer") },
    { value: "route", label: t("routes.keyRoute") },
  ]
  return (
    <Field data-invalid={messages.length > 0}>
      <FieldLabel htmlFor={id}>{t("routes.key")}</FieldLabel>
      <div className="flex gap-2">
        <NativeSelect
          id={id}
          value={kind}
          className="shrink-0"
          disabled={readOnly}
          onChange={(event) => {
            const next = event.target.value
            set(
              next === "client_ip"
                ? undefined
                : next === "header"
                  ? { header }
                  : next
            )
          }}
        >
          {kinds.map((option) => (
            <NativeSelectOption key={option.value} value={option.value}>
              {option.label}
            </NativeSelectOption>
          ))}
        </NativeSelect>
        {kind === "header" && (
          <Input
            value={header}
            placeholder="X-API-Key"
            className="font-mono"
            disabled={readOnly}
            aria-label={t("routes.keyHeader")}
            onChange={(event) => set({ header: event.target.value })}
          />
        )}
      </div>
      <FieldError errors={messages.map((message) => ({ message }))} />
    </Field>
  )
}
