import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeftIcon,
  CheckIcon,
  InfoIcon,
  PlusIcon,
  RotateCwIcon,
  SaveIcon,
  Trash2Icon,
} from "lucide-react"
import { type ComponentType, type ReactNode, useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useLocation, useNavigate, useParams } from "react-router"

import { DraftProvider } from "@/components/draft"
import { ErrorAlert } from "@/components/error-alert"
import { PageHeader } from "@/components/page-header"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button, buttonVariants } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table as DataTable,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  ApiError,
  api,
  type JsonObject,
  type Table,
  type Tagged,
} from "@/lib/api"
import { isObject, issuePath } from "@/lib/draft"
import { useStatus } from "@/lib/queries"

/** What the dashboard knows of a kind of entity. */
export interface Kind {
  /** Its table in the configuration and the Admin API. */
  table: Table
  /** Path of its list in the dashboard, such as `/routes`. */
  path: string
  /** The form of one entity. */
  Form: ComponentType
  /** A new entity before any change. */
  fresh: JsonObject
}

/** A column of a list of entities. */
export interface Column {
  /** Its heading. */
  title: string
  /** What it shows of entity `name`. */
  render: (entity: JsonObject, name: string) => ReactNode
}

/** Segment of the path of a new entity: no name has it, as names do not take `~`. */
export const NEW = "~new"

/** The names of the entities of `table`, in order. */
export function useNames(table: Table): string[] {
  const entities = useQuery({
    queryKey: ["entities", table],
    queryFn: () => api.entities(table),
  })
  return Object.keys(entities.data ?? {}).sort()
}

/** Whether the dynamic settings can only be looked at: they come from the file, or the status
 * is not known yet. */
export function useReadOnly(): boolean {
  return useStatus().data?.config.source !== "db"
}

/**
 * The entities of `table` in a card under `title`, each linking to its page under `path`, with
 * the `columns` and a button for a new one.
 */
export function EntityList({
  table,
  path,
  title,
  description,
  columns,
}: {
  table: Table
  path: string
  title: string
  description: string
  columns: Column[]
}) {
  const { t } = useTranslation()
  const readOnly = useReadOnly()
  const entities = useQuery({
    queryKey: ["entities", table],
    queryFn: () => api.entities(table),
  })
  return (
    <Card className="mb-6">
      <CardHeader>
        <CardTitle className="text-lg">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
        {!readOnly && (
          <CardAction>
            <Link
              to={`${path}/${NEW}`}
              className={buttonVariants({ variant: "outline", size: "sm" })}
            >
              <PlusIcon />
              {t("entity.new")}
            </Link>
          </CardAction>
        )}
      </CardHeader>
      <CardContent>
        {entities.isPending && <Skeleton className="h-24" />}
        {entities.isError && <ErrorAlert error={entities.error} />}
        {entities.isSuccess &&
          (Object.keys(entities.data).length === 0 ? (
            <p className="text-muted-foreground">{t("entity.empty")}</p>
          ) : (
            <DataTable>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("entity.name")}</TableHead>
                  {columns.map((column) => (
                    <TableHead key={column.title}>{column.title}</TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(entities.data).map(([name, entity]) => (
                  <TableRow key={name}>
                    <TableCell className="font-medium">
                      <Link to={`${path}/${name}`} className="hover:underline">
                        {name}
                      </Link>
                    </TableCell>
                    {columns.map((column) => (
                      <TableCell key={column.title}>
                        {column.render(entity, name)}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </DataTable>
          ))}
      </CardContent>
    </Card>
  )
}

/** The page of one entity of `kind`, or of a new one: its form, its JSON, saving and
 * deleting. */
export function EntityEditor({ kind }: { kind: Kind }) {
  const { t } = useTranslation()
  const params = useParams()
  // Grows with every reload, which starts the edits over.
  const [generation, setGeneration] = useState(0)
  const loaded = useQuery({
    queryKey: ["entity", kind.table, params.name],
    queryFn: () => api.entity(kind.table, params.name ?? ""),
    enabled: params.name !== undefined,
    // Edits stay until they are saved: the entity is not loaded again behind them.
    staleTime: Number.POSITIVE_INFINITY,
    refetchOnWindowFocus: false,
  })
  // Keyed by the table too: pages of different kinds must not share their edits.
  if (params.name === undefined) {
    return (
      <Editor
        key={`${kind.table} ${NEW}`}
        kind={kind}
        loaded={null}
        reload={() => {}}
      />
    )
  }
  const missing =
    loaded.error instanceof ApiError && loaded.error.status === 404
  if (missing) {
    return (
      <ErrorAlert
        error={new Error(t("entity.notFound", { name: params.name }))}
      />
    )
  }
  if (loaded.isPending) {
    return <Skeleton className="h-64" />
  }
  if (loaded.isError) {
    return <ErrorAlert error={loaded.error} />
  }
  return (
    <Editor
      key={`${kind.table} ${params.name} ${generation}`}
      kind={kind}
      name={params.name}
      loaded={loaded.data}
      reload={() =>
        void loaded.refetch().then(() => setGeneration((count) => count + 1))
      }
    />
  )
}

/** Editor of entity `name` as `loaded`, or of a new entity without either. */
function Editor({
  kind,
  name: saved,
  loaded,
  reload,
}: {
  kind: Kind
  name?: string
  loaded: Tagged<JsonObject> | null
  reload: () => void
}) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const location = useLocation()
  const queryClient = useQueryClient()
  const readOnly = useReadOnly()
  // The version that created the entity, when the page of a new entity led here.
  const created = (location.state as { created?: number | null } | null)
    ?.created
  const [name, setName] = useState(saved ?? "")
  const [draft, setDraft] = useState<JsonObject>(loaded?.value ?? kind.fresh)
  const [etag, setEtag] = useState(loaded?.etag ?? null)
  const [tab, setTab] = useState("form")
  const [json, setJson] = useState("")
  const [jsonError, setJsonError] = useState<string | null>(null)
  const [confirming, setConfirming] = useState(false)
  const creating = saved === undefined

  const save = useMutation({
    mutationFn: (value: JsonObject) =>
      api.saveEntity(kind.table, name, value, creating ? null : etag),
    onSuccess: (answer) => {
      setEtag(answer.etag)
      void queryClient.invalidateQueries()
      if (creating) {
        void navigate(`${kind.path}/${name}`, {
          replace: true,
          state: { created: answer.value.version },
        })
      }
    },
  })
  const remove = useMutation({
    mutationFn: () => api.deleteEntity(kind.table, name, etag),
    onSuccess: () => {
      // The entity is gone: it is forgotten rather than loaded again.
      queryClient.removeQueries({ queryKey: ["entity", kind.table, name] })
      void queryClient.invalidateQueries()
      void navigate(kind.path)
    },
  })
  /** Reads the JSON tab; null when it does not hold an object, with the problem shown. */
  function parseJson(): JsonObject | null {
    try {
      const value: unknown = JSON.parse(json)
      if (!isObject(value as JsonObject)) {
        setJsonError(t("entity.notObject"))
        return null
      }
      setJsonError(null)
      return value as JsonObject
    } catch (error) {
      setJsonError(t("entity.invalidJson", { error: String(error) }))
      return null
    }
  }

  /** Switches between the form and the JSON, carrying the edits over. */
  function switchTab(next: string) {
    if (next === "json") {
      setJson(JSON.stringify(draft, null, 2))
      setJsonError(null)
      setTab(next)
    } else {
      const value = parseJson()
      if (value !== null) {
        setDraft(value)
        setTab(next)
      }
    }
  }

  /** Saves the entity as the open tab shows it. */
  function submit() {
    const value = tab === "json" ? parseJson() : draft
    if (value === null) {
      return
    }
    setDraft(value)
    save.mutate(value)
  }

  const failure = save.error ?? remove.error
  const issues =
    failure instanceof ApiError
      ? failure.details.map((issue) => ({
          path: issuePath(issue, kind.table, name),
          message: issue.message,
        }))
      : []
  const conflict = failure instanceof ApiError && failure.status === 412
  return (
    <>
      <Link
        to={kind.path}
        className="mb-4 inline-flex items-center gap-1 text-muted-foreground text-sm hover:text-foreground"
      >
        <ArrowLeftIcon className="size-4" />
        {t(`${kind.table}.title`)}
      </Link>
      <PageHeader title={creating ? t(`${kind.table}.new`) : name}>
        {!readOnly && (
          <div className="flex gap-2">
            {!creating && (
              <Button variant="outline" onClick={() => setConfirming(true)}>
                <Trash2Icon />
                {t("entity.delete")}
              </Button>
            )}
            <Button disabled={save.isPending} onClick={submit}>
              <SaveIcon />
              {t("entity.save")}
            </Button>
          </div>
        )}
      </PageHeader>
      {readOnly && (
        <Alert className="mb-4">
          <InfoIcon />
          <AlertDescription>{t("entity.fileMode")}</AlertDescription>
        </Alert>
      )}
      {created !== undefined && save.isIdle && (
        <Alert className="mb-4">
          <CheckIcon />
          <AlertDescription>
            {t("entity.created", { version: created })}
          </AlertDescription>
        </Alert>
      )}
      {save.isSuccess && (
        <Alert className="mb-4">
          <CheckIcon />
          <AlertDescription>
            {save.data.value.changed
              ? t("entity.saved", { version: save.data.value.version })
              : t("entity.unchanged")}
          </AlertDescription>
        </Alert>
      )}
      {failure !== null && (
        <ErrorAlert
          error={failure}
          message={
            conflict
              ? creating
                ? t("entity.taken")
                : t("entity.conflict")
              : remove.isError && issues.length > 0
                ? t("entity.inUse")
                : undefined
          }
        />
      )}
      {conflict && !creating && (
        <Button variant="outline" className="mb-4" onClick={reload}>
          <RotateCwIcon />
          {t("entity.reload")}
        </Button>
      )}
      {creating && (
        <Field className="mb-6 max-w-sm">
          <FieldLabel htmlFor="entity-name">{t("entity.name")}</FieldLabel>
          <Input
            id="entity-name"
            value={name}
            placeholder="api"
            onChange={(event) => setName(event.target.value)}
          />
          <FieldDescription>{t("entity.nameHint")}</FieldDescription>
        </Field>
      )}
      <Tabs value={tab} onValueChange={(next) => switchTab(String(next))}>
        <TabsList className="mb-4">
          <TabsTrigger value="form">{t("entity.form")}</TabsTrigger>
          <TabsTrigger value="json">JSON</TabsTrigger>
        </TabsList>
        <TabsContent value="form">
          <DraftProvider
            draft={draft}
            update={(change) => setDraft(change)}
            issues={issues}
            readOnly={readOnly}
          >
            <kind.Form />
          </DraftProvider>
        </TabsContent>
        <TabsContent value="json">
          <Field data-invalid={jsonError !== null}>
            <Textarea
              value={json}
              rows={Math.max(12, json.split("\n").length + 1)}
              disabled={readOnly}
              className="font-mono"
              aria-invalid={jsonError !== null}
              onChange={(event) => setJson(event.target.value)}
            />
            <FieldDescription>{t("entity.jsonHint")}</FieldDescription>
            {jsonError && (
              <p className="text-destructive text-sm">{jsonError}</p>
            )}
          </Field>
        </TabsContent>
      </Tabs>
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("entity.deleteTitle", { name })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("entity.deleteText", { name })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t("entity.cancel")}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={() => {
                setConfirming(false)
                remove.mutate()
              }}
            >
              {t("entity.delete")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}
