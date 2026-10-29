import { useMutation } from "@tanstack/react-query"
import { type FormEvent, useState } from "react"
import { useTranslation } from "react-i18next"
import { Navigate, useLocation } from "react-router"

import { ErrorAlert } from "@/components/error-alert"
import { LanguageSwitch } from "@/components/language-switch"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ApiError, api } from "@/lib/api"
import { setToken, useToken } from "@/lib/auth"

/** Sign-in page: checks a token against the Admin API and keeps it. */
export function LoginPage() {
  const { t } = useTranslation()
  const location = useLocation()
  const stored = useToken()
  const [token, setInput] = useState("")
  const signIn = useMutation({
    mutationFn: (candidate: string) => api.status(candidate),
    onSuccess: (_, candidate) => setToken(candidate),
  })

  // Signed in: go on to the page that asked for the sign-in.
  if (stored !== null) {
    const from = (location.state as { from?: string } | null)?.from
    return <Navigate to={from ?? "/"} replace />
  }

  /** Checks the entered token. */
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    signIn.mutate(token.trim())
  }

  const wrongToken =
    signIn.error instanceof ApiError && signIn.error.status === 401
  return (
    <div className="flex min-h-svh flex-col items-center justify-center gap-4 p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>{t("login.title")}</CardTitle>
          <CardDescription>{t("login.description")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={submit} className="grid gap-4">
            <div className="grid gap-2">
              <Label htmlFor="token">{t("login.token")}</Label>
              <Input
                id="token"
                type="password"
                autoComplete="off"
                required
                value={token}
                onChange={(event) => setInput(event.target.value)}
              />
            </div>
            {signIn.error && (
              <ErrorAlert
                error={signIn.error}
                message={wrongToken ? t("login.wrongToken") : undefined}
              />
            )}
            <Button
              type="submit"
              disabled={signIn.isPending || token.trim() === ""}
            >
              {t("login.submit")}
            </Button>
          </form>
        </CardContent>
      </Card>
      <LanguageSwitch />
    </div>
  )
}
