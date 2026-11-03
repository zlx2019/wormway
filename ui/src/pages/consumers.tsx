import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  ArrowLeftIcon,
  CopyIcon,
  InfoIcon,
  KeyRoundIcon,
  PlusIcon,
  Trash2Icon,
} from "lucide-react"
import { useState } from "react"
import { useTranslation } from "react-i18next"
import { Link, useNavigate, useParams } from "react-router"

import { EntityList, useReadOnly } from "@/components/entity"
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
import { Button } from "@/components/ui/button"
import {
  Card,
  CardAction,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Field,
  FieldDescription,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  ApiError,
  api,
  type JsonObject,
  type NewApiKey,
  type Tagged,
} from "@/lib/api"
import { without } from "@/lib/draft"

/** The consumers with their credentials, and the settings that check JWTs. */
export function ConsumersPage() {
  const { t } = useTranslation()
  return (
    <>
      <EntityList
        table="consumers"
        path="/consumers"
        title={t("consumers.title")}
        description={t("consumers.description")}
        columns={[
          {
            title: t("consumers.password"),
            render: (consumer) =>
              consumer.password_hash === undefined
                ? "—"
                : t("consumers.passwordSet"),
          },
          {
            title: t("consumers.apiKeys"),
            render: (consumer) =>
              Array.isArray(consumer.api_keys)
                ? String(consumer.api_keys.length)
                : "0",
          },
        ]}
      />
      <EntityList
        table="jwt"
        path="/jwt"
        title={t("jwt.title")}
        description={t("jwt.description")}
        columns={[
          {
            title: t("jwt.algorithm"),
            render: (settings) => String(settings.algorithm),
          },
          {
            title: t("jwt.issuer"),
            render: (settings) =>
              typeof settings.issuer === "string" ? settings.issuer : "—",
          },
        ]}
      />
    </>
  )
}

/** The page of one consumer, or of a new one. */
export function ConsumerPage() {
  const name = useParams().name
  return name === undefined ? (
    <NewConsumer />
  ) : (
    <Consumer key={name} name={name} />
  )
}

/** A link back to the consumers. */
function BackLink() {
  const { t } = useTranslation()
  return (
    <Link
      to="/consumers"
      className="mb-4 inline-flex items-center gap-1 text-muted-foreground text-sm hover:text-foreground"
    >
      <ArrowLeftIcon className="size-4" />
      {t("consumers.title")}
    </Link>
  )
}

/** Creates a consumer, with a password if one is given. */
function NewConsumer() {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [name, setName] = useState("")
  const [password, setPassword] = useState("")
  const create = useMutation({
    mutationFn: async () => {
      const created = await api.saveEntity("consumers", name, {}, null)
      if (password !== "") {
        await api.setPassword(name, password, created.etag ?? "*")
      }
    },
    onSettled: () => void queryClient.invalidateQueries(),
    onSuccess: () => void navigate(`/consumers/${name}`),
  })
  return (
    <>
      <BackLink />
      <PageHeader title={t("consumers.new")} />
      {create.isError && <ErrorAlert error={create.error} />}
      <form
        className="max-w-sm"
        onSubmit={(event) => {
          event.preventDefault()
          create.mutate()
        }}
      >
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="consumer-name">{t("entity.name")}</FieldLabel>
            <Input
              id="consumer-name"
              value={name}
              placeholder="alice"
              onChange={(event) => setName(event.target.value)}
            />
            <FieldDescription>{t("consumers.nameHint")}</FieldDescription>
          </Field>
          <Field>
            <FieldLabel htmlFor="consumer-password">
              {t("consumers.password")}
            </FieldLabel>
            <Input
              id="consumer-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
            <FieldDescription>{t("consumers.passwordHint")}</FieldDescription>
          </Field>
          <Button type="submit" className="w-fit" disabled={create.isPending}>
            <PlusIcon />
            {t("consumers.create")}
          </Button>
        </FieldGroup>
      </form>
    </>
  )
}

/** Consumer `name`: its password, its API keys, and its removal. */
function Consumer({ name }: { name: string }) {
  const { t } = useTranslation()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const readOnly = useReadOnly()
  const loaded = useQuery({
    queryKey: ["entity", "consumers", name],
    queryFn: () => api.entity("consumers", name),
  })
  const [settingPassword, setSettingPassword] = useState(false)
  const [newKey, setNewKey] = useState<NewApiKey | null>(null)
  const [deleting, setDeleting] = useState(false)
  // Every change goes through here, so that one error shows at a time.
  const change = useMutation({
    mutationFn: (
      action: (consumer: Tagged<JsonObject>) => Promise<unknown>
    ) => {
      if (loaded.data === undefined) {
        return Promise.reject(new Error(t("entity.notLoaded")))
      }
      return action(loaded.data)
    },
    onSettled: () => void queryClient.invalidateQueries(),
  })

  if (loaded.error instanceof ApiError && loaded.error.status === 404) {
    return <ErrorAlert error={new Error(t("entity.notFound", { name }))} />
  }
  if (loaded.isPending) {
    return <Skeleton className="h-64" />
  }
  if (loaded.isError) {
    return <ErrorAlert error={loaded.error} />
  }

  const consumer = loaded.data.value
  const keys = Array.isArray(consumer.api_keys)
    ? consumer.api_keys.map(String)
    : []
  const hasPassword = consumer.password_hash !== undefined
  const etag = loaded.data.etag
  const conflict =
    change.error instanceof ApiError && change.error.status === 412

  /** Saves `next` in place of the consumer. */
  const replace = (next: JsonObject) =>
    change.mutate(() => api.saveEntity("consumers", name, next, etag))
  return (
    <>
      <BackLink />
      <PageHeader title={name} description={t("consumers.basicUser", { name })}>
        {!readOnly && (
          <Button variant="outline" onClick={() => setDeleting(true)}>
            <Trash2Icon />
            {t("entity.delete")}
          </Button>
        )}
      </PageHeader>
      {readOnly && (
        <Alert className="mb-4">
          <InfoIcon />
          <AlertDescription>{t("entity.fileMode")}</AlertDescription>
        </Alert>
      )}
      {change.isError && (
        <ErrorAlert
          error={change.error}
          message={conflict ? t("consumers.conflict") : undefined}
        />
      )}
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("consumers.password")}</CardTitle>
          <CardDescription>
            {hasPassword
              ? t("consumers.passwordSet")
              : t("consumers.noPassword")}
          </CardDescription>
          {!readOnly && (
            <CardAction className="flex gap-2">
              {hasPassword && (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={change.isPending}
                  onClick={() => replace(without(consumer, ["password_hash"]))}
                >
                  {t("consumers.removePassword")}
                </Button>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSettingPassword(true)}
              >
                <KeyRoundIcon />
                {t("consumers.setPassword")}
              </Button>
            </CardAction>
          )}
        </CardHeader>
      </Card>
      <Card className="mb-6">
        <CardHeader>
          <CardTitle>{t("consumers.apiKeys")}</CardTitle>
          <CardDescription>{t("consumers.apiKeysHint")}</CardDescription>
          {!readOnly && (
            <CardAction>
              <Button
                variant="outline"
                size="sm"
                disabled={change.isPending}
                onClick={() =>
                  change.mutate(async (current) => {
                    const answer = await api.addApiKey(
                      name,
                      current.etag ?? "*"
                    )
                    setNewKey(answer.value)
                  })
                }
              >
                <PlusIcon />
                {t("consumers.newKey")}
              </Button>
            </CardAction>
          )}
        </CardHeader>
        <CardContent>
          {keys.length === 0 ? (
            <p className="text-muted-foreground">{t("consumers.noKeys")}</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {keys.map((key) => (
                <li key={key} className="flex items-center gap-2">
                  <code className="truncate text-xs">{key}</code>
                  {!readOnly && (
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      disabled={change.isPending}
                      aria-label={t("consumers.removeKey")}
                      onClick={() => {
                        const rest = keys.filter((other) => other !== key)
                        replace(
                          rest.length === 0
                            ? without(consumer, ["api_keys"])
                            : { ...consumer, api_keys: rest }
                        )
                      }}
                    >
                      <Trash2Icon />
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
      <PasswordDialog
        open={settingPassword}
        onOpenChange={setSettingPassword}
        onSubmit={(password) => {
          setSettingPassword(false)
          change.mutate((current) =>
            api.setPassword(name, password, current.etag ?? "*")
          )
        }}
      />
      <KeyDialog apiKey={newKey} onClose={() => setNewKey(null)} />
      <AlertDialog open={deleting} onOpenChange={setDeleting}>
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
              onClick={() => {
                setDeleting(false)
                change.mutate(async () => {
                  await api.deleteEntity("consumers", name, etag)
                  // The consumer is gone: it is forgotten rather than loaded again.
                  queryClient.removeQueries({
                    queryKey: ["entity", "consumers", name],
                  })
                  await navigate("/consumers")
                })
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

/** Asks for a new password twice. */
function PasswordDialog({
  open,
  onOpenChange,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onSubmit: (password: string) => void
}) {
  const { t } = useTranslation()
  const [password, setPassword] = useState("")
  const [again, setAgain] = useState("")
  const mismatch = again !== "" && again !== password
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        setPassword("")
        setAgain("")
        onOpenChange(next)
      }}
    >
      <DialogContent>
        <form
          className="grid gap-4"
          onSubmit={(event) => {
            event.preventDefault()
            if (password !== "" && password === again) {
              onSubmit(password)
              setPassword("")
              setAgain("")
            }
          }}
        >
          <DialogHeader>
            <DialogTitle>{t("consumers.setPassword")}</DialogTitle>
            <DialogDescription>{t("consumers.passwordHint")}</DialogDescription>
          </DialogHeader>
          <Field>
            <FieldLabel htmlFor="password-new">
              {t("consumers.newPassword")}
            </FieldLabel>
            <Input
              id="password-new"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </Field>
          <Field data-invalid={mismatch}>
            <FieldLabel htmlFor="password-again">
              {t("consumers.passwordAgain")}
            </FieldLabel>
            <Input
              id="password-again"
              type="password"
              autoComplete="new-password"
              value={again}
              aria-invalid={mismatch}
              onChange={(event) => setAgain(event.target.value)}
            />
            <FieldError
              errors={mismatch ? [{ message: t("consumers.mismatch") }] : []}
            />
          </Field>
          <DialogFooter>
            <Button
              type="submit"
              disabled={password === "" || password !== again}
            >
              {t("consumers.savePassword")}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Shows a new API key, the only time that it can be seen. */
function KeyDialog({
  apiKey,
  onClose,
}: {
  apiKey: NewApiKey | null
  onClose: () => void
}) {
  const { t } = useTranslation()
  const [copied, setCopied] = useState(false)
  return (
    <Dialog
      open={apiKey !== null}
      onOpenChange={(open) => {
        if (!open) {
          setCopied(false)
          onClose()
        }
      }}
    >
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("consumers.keyTitle")}</DialogTitle>
          <DialogDescription>{t("consumers.keyOnce")}</DialogDescription>
        </DialogHeader>
        <div className="flex gap-2">
          <Input
            readOnly
            value={apiKey?.key ?? ""}
            className="font-mono text-xs"
            aria-label={t("consumers.apiKeys")}
            onFocus={(event) => event.target.select()}
          />
          <Button
            variant="outline"
            onClick={() =>
              void navigator.clipboard
                .writeText(apiKey?.key ?? "")
                // Without the clipboard, the key stays there to copy by hand.
                .then(
                  () => setCopied(true),
                  () => setCopied(false)
                )
            }
          >
            <CopyIcon />
            {copied ? t("consumers.copied") : t("consumers.copy")}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
