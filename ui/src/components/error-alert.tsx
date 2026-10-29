import { CircleAlertIcon } from "lucide-react"
import { useTranslation } from "react-i18next"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { ApiError } from "@/lib/api"

/**
 * Explains a failed request with the message of Wormway and the problem of each setting.
 * `message` replaces the message, for errors the page explains better itself.
 */
export function ErrorAlert({
  error,
  message,
}: {
  error: Error
  message?: string
}) {
  const { t } = useTranslation()
  const details = error instanceof ApiError ? error.details : []
  return (
    <Alert variant="destructive" className="mb-4">
      <CircleAlertIcon />
      <AlertTitle>{t("common.failed")}</AlertTitle>
      <AlertDescription>
        <p>{message ?? error.message}</p>
        {details.length > 0 && (
          <ul className="list-disc pl-4">
            {details.map((issue) => (
              <li key={`${issue.path}: ${issue.message}`}>
                <code>{issue.path}</code>: {issue.message}
              </li>
            ))}
          </ul>
        )}
      </AlertDescription>
    </Alert>
  )
}
