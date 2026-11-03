import { PlusIcon, Trash2Icon } from "lucide-react"
import {
  createContext,
  type ReactNode,
  useContext,
  useEffect,
  useId,
  useState,
} from "react"
import { useTranslation } from "react-i18next"

import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
  FieldLegend,
  FieldSet,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import type { Json, JsonObject } from "@/lib/api"
import { getIn, isObject, messagesAt, setIn } from "@/lib/draft"

/** An entity being edited, as the fields inside a `DraftProvider` see it. */
interface DraftState {
  /** The entity as edited so far. */
  draft: JsonObject
  /** Applies `change` to the entity. */
  update: (change: (draft: JsonObject) => JsonObject) => void
  /** Problems that Wormway found, with paths inside the entity such as `match.paths.0`. */
  issues: { path: string; message: string }[]
  /** Whether the entity can only be looked at. */
  readOnly: boolean
}

/** The entity that the fields edit. */
const DraftContext = createContext<DraftState | null>(null)

/** Lets the fields inside edit an entity. */
export function DraftProvider({
  children,
  ...state
}: DraftState & { children: ReactNode }) {
  return <DraftContext value={state}>{children}</DraftContext>
}

/** The whole entity being edited, for choices that change several settings at once. */
export function useDraft(): DraftState {
  const state = useContext(DraftContext)
  if (state === null) {
    throw new Error("settings are edited inside a DraftProvider")
  }
  return state
}

/**
 * The setting at `path`, such as `match.hosts`: its value, a setter that removes it with
 * undefined so that it takes its default, its problems and whether it can be changed.
 */
export function useSetting(path: string) {
  const { draft, update, issues, readOnly } = useDraft()
  return {
    value: getIn(draft, path),
    set: (next: Json | undefined) =>
      update((current) => setIn(current, path, next)),
    messages: messagesAt(issues, path),
    exactMessages: issues
      .filter((issue) => issue.path === path)
      .map((issue) => issue.message),
    readOnly,
  }
}

/** What every setting shows besides its input. */
interface SettingProps {
  /** Where the setting is in the entity. */
  path: string
  /** Its name. */
  label: string
  /** A sentence that explains it. */
  hint?: string
}

/** A setting with its label, hint and problems around its input. */
function Row({
  id,
  label,
  hint,
  messages,
  children,
}: {
  id: string
  label: string
  hint?: string
  messages: string[]
  children: ReactNode
}) {
  return (
    <Field data-invalid={messages.length > 0}>
      <FieldLabel htmlFor={id}>{label}</FieldLabel>
      {children}
      {hint && <FieldDescription>{hint}</FieldDescription>}
      <FieldError errors={messages.map((message) => ({ message }))} />
    </Field>
  )
}

/** A text setting, on several lines with `multiline`; an empty one takes its default. */
export function TextSetting({
  path,
  label,
  hint,
  placeholder,
  multiline = false,
}: SettingProps & { placeholder?: string; multiline?: boolean }) {
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  const Control = multiline ? Textarea : Input
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      <Control
        id={id}
        value={typeof value === "string" ? value : ""}
        placeholder={placeholder}
        disabled={readOnly}
        aria-invalid={messages.length > 0}
        onChange={(event) =>
          set(event.target.value === "" ? undefined : event.target.value)
        }
      />
    </Row>
  )
}

/** A whole number; an empty one takes its default. */
export function NumberSetting({
  path,
  label,
  hint,
  placeholder,
}: SettingProps & { placeholder?: string }) {
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      <Input
        id={id}
        type="number"
        value={typeof value === "number" ? value : ""}
        placeholder={placeholder}
        disabled={readOnly}
        aria-invalid={messages.length > 0}
        onChange={(event) =>
          set(
            event.target.value === "" ? undefined : Number(event.target.value)
          )
        }
      />
    </Row>
  )
}

/** One of the choices of a select. */
export interface Option {
  value: string
  label: string
}

/**
 * A choice among `options`. With `implied`, that choice is the default: it is shown while the
 * setting is left out, and choosing it leaves the setting out again. With `fallback`, a first
 * choice so named leaves the setting out instead.
 */
export function SelectSetting({
  path,
  label,
  hint,
  options,
  implied,
  fallback,
}: SettingProps & {
  options: readonly Option[]
  implied?: string
  fallback?: string
}) {
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      <NativeSelect
        id={id}
        value={typeof value === "string" ? value : (implied ?? "")}
        disabled={readOnly}
        aria-invalid={messages.length > 0}
        onChange={(event) => {
          const next = event.target.value
          set(next === "" || next === implied ? undefined : next)
        }}
      >
        {fallback !== undefined && (
          <NativeSelectOption value="">{fallback}</NativeSelectOption>
        )}
        {options.map((option) => (
          <NativeSelectOption key={option.value} value={option.value}>
            {option.label}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </Row>
  )
}

/** A switch. The setting is left out while it is at `fallback`, its default. */
export function SwitchSetting({
  path,
  label,
  hint,
  fallback = false,
}: SettingProps & { fallback?: boolean }) {
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  return (
    <Field orientation="horizontal" data-invalid={messages.length > 0}>
      <Switch
        id={id}
        checked={typeof value === "boolean" ? value : fallback}
        disabled={readOnly}
        onCheckedChange={(on) => set(on === fallback ? undefined : on)}
      />
      <div className="flex flex-col gap-1">
        <FieldLabel htmlFor={id}>{label}</FieldLabel>
        {hint && <FieldDescription>{hint}</FieldDescription>}
        <FieldError errors={messages.map((message) => ({ message }))} />
      </div>
    </Field>
  )
}

/** Splits text into its lines without the blank ones. */
function lines(text: string): string[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line !== "")
}

/** A list of texts, or of numbers with `numbers`, one per line. An empty list takes its
 * default, or stays as an empty list with `keep`, for lists that the entity must have. */
export function LinesSetting({
  path,
  label,
  hint,
  placeholder,
  numbers = false,
  keep = false,
}: SettingProps & { placeholder?: string; numbers?: boolean; keep?: boolean }) {
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  const joined = Array.isArray(value) ? value.map(String).join("\n") : ""
  const [text, setText] = useState(joined)
  // Takes changes made elsewhere, such as in the JSON tab, unless the text says the same.
  useEffect(() => {
    setText((current) =>
      lines(current).join("\n") === joined ? current : joined
    )
  }, [joined])
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      <Textarea
        id={id}
        value={text}
        rows={Math.max(2, text.split("\n").length)}
        placeholder={placeholder}
        disabled={readOnly}
        aria-invalid={messages.length > 0}
        className="font-mono"
        onChange={(event) => {
          setText(event.target.value)
          const items = lines(event.target.value)
          const next = numbers ? items.map(Number) : items
          set(next.length === 0 && !keep ? undefined : next)
        }}
      />
    </Row>
  )
}

/**
 * A choice of names among `names`, such as the listeners of a route. An empty choice takes its
 * default, or stays as an empty list with `keep`. Names chosen before that no longer exist stay
 * listed, to remove them.
 */
export function NamesSetting({
  path,
  label,
  hint,
  names,
  keep = false,
}: SettingProps & { names: string[]; keep?: boolean }) {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  const chosen = Array.isArray(value) ? value.map(String) : []
  const all = [...new Set([...names, ...chosen])].sort()
  /** Adds `name` to the choice or takes it out. */
  function toggle(name: string, on: boolean) {
    const next = on
      ? [...chosen, name]
      : chosen.filter((other) => other !== name)
    set(next.length === 0 && !keep ? undefined : next)
  }
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      {all.length === 0 ? (
        <p className="text-muted-foreground text-sm">{t("form.noNames")}</p>
      ) : (
        <div id={id} className="flex flex-wrap gap-x-4 gap-y-2">
          {all.map((name) => (
            <Field key={name} orientation="horizontal" className="w-auto">
              <Checkbox
                id={`${id}-${name}`}
                checked={chosen.includes(name)}
                disabled={readOnly}
                onCheckedChange={(on) => toggle(name, on)}
              />
              <FieldLabel htmlFor={`${id}-${name}`} className="font-normal">
                {name}
              </FieldLabel>
            </Field>
          ))}
        </div>
      )}
    </Row>
  )
}

/** A group of settings under a title. */
export function Group({
  title,
  hint,
  children,
}: {
  title: string
  hint?: string
  children: ReactNode
}) {
  return (
    <div className="rounded-lg border p-4">
      <FieldSet>
        <FieldLegend>{title}</FieldLegend>
        {hint && <FieldDescription>{hint}</FieldDescription>}
        <FieldGroup>{children}</FieldGroup>
      </FieldSet>
    </div>
  )
}

/**
 * Settings that the entity has only when they are switched on, such as a rate limit:
 * switching on puts `initial` at `path`, switching off removes it.
 */
export function Section({
  path,
  title,
  hint,
  initial,
  children,
}: {
  path: string
  title: string
  hint?: string
  initial: Json
  children?: ReactNode
}) {
  const id = useId()
  const { value, set, exactMessages, readOnly } = useSetting(path)
  const on = value !== undefined
  return (
    <div className="rounded-lg border p-4">
      <FieldSet>
        <div className="flex items-center justify-between gap-4">
          <FieldLegend className="mb-0">
            <label htmlFor={id}>{title}</label>
          </FieldLegend>
          <Switch
            id={id}
            checked={on}
            disabled={readOnly}
            onCheckedChange={(next) => set(next ? initial : undefined)}
          />
        </div>
        {hint && <FieldDescription>{hint}</FieldDescription>}
        <FieldError errors={exactMessages.map((message) => ({ message }))} />
        {on && children && <FieldGroup>{children}</FieldGroup>}
      </FieldSet>
    </div>
  )
}

/**
 * A list setting edited row by row, such as the targets of an upstream: `render` shows one
 * item with a way to change it, and a new row starts as `fresh`. An empty list takes its
 * default, or stays as an empty list with `keep`.
 */
export function RowsSetting({
  path,
  label,
  hint,
  fresh,
  keep = false,
  render,
}: SettingProps & {
  fresh: Json
  keep?: boolean
  render: (
    item: Json,
    change: (next: Json) => void,
    readOnly: boolean
  ) => ReactNode
}) {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  const items = Array.isArray(value) ? value : []
  /** Replaces the list, leaving it out when empty unless it is kept. */
  function replace(next: Json[]) {
    set(next.length === 0 && !keep ? undefined : next)
  }
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      <div id={id} className="flex flex-col gap-2">
        {items.map((item, index) => (
          <div
            // biome-ignore lint/suspicious/noArrayIndexKey: rows have no identity but their place
            key={index}
            className="flex items-center gap-2"
          >
            {render(
              item,
              (next) =>
                replace(items.map((old, i) => (i === index ? next : old))),
              readOnly
            )}
            <Button
              variant="ghost"
              size="icon"
              disabled={readOnly}
              aria-label={t("form.remove")}
              onClick={() => replace(items.filter((_, i) => i !== index))}
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
          onClick={() => replace([...items, fresh])}
        >
          <PlusIcon />
          {t("form.add")}
        </Button>
      </div>
    </Row>
  )
}

/** A choice that is not one setting, such as what a route does: `onChange` changes the
 * settings that it stands for. */
export function Choice({
  label,
  hint,
  value,
  options,
  onChange,
}: {
  label: string
  hint?: string
  value: string
  options: readonly Option[]
  onChange: (value: string) => void
}) {
  const id = useId()
  const { readOnly } = useDraft()
  return (
    <Row id={id} label={label} hint={hint} messages={[]}>
      <NativeSelect
        id={id}
        value={value}
        disabled={readOnly}
        onChange={(event) => onChange(event.target.value)}
      >
        {options.map((option) => (
          <NativeSelectOption key={option.value} value={option.value}>
            {option.label}
          </NativeSelectOption>
        ))}
      </NativeSelect>
    </Row>
  )
}

/** A secret that the configuration refers to: an environment variable, `{ env }`, or a file,
 * `{ file }`. */
export function SecretSetting({ path, label, hint }: SettingProps) {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting(path)
  const kind = isObject(value) && "file" in value ? "file" : "env"
  const text = isObject(value) ? String(value[kind] ?? "") : ""
  return (
    <Row id={id} label={label} hint={hint} messages={messages}>
      <div className="flex gap-2">
        <NativeSelect
          value={kind}
          className="shrink-0"
          disabled={readOnly}
          aria-label={t("form.secretKind")}
          onChange={(event) => set({ [event.target.value]: text })}
        >
          <NativeSelectOption value="env">{t("form.env")}</NativeSelectOption>
          <NativeSelectOption value="file">{t("form.file")}</NativeSelectOption>
        </NativeSelect>
        <Input
          id={id}
          value={text}
          className="font-mono"
          placeholder={kind === "env" ? "JWT_SECRET" : "secrets/jwt.key"}
          disabled={readOnly}
          aria-invalid={messages.length > 0}
          onChange={(event) => set({ [kind]: event.target.value })}
        />
      </div>
    </Row>
  )
}
