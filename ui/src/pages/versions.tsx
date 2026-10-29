import { useInfiniteQuery } from "@tanstack/react-query"
import { InfoIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { Link } from "react-router"

import { ErrorAlert } from "@/components/error-alert"
import { PageHeader } from "@/components/page-header"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { api, PAGE_SIZE } from "@/lib/api"
import { formatTime } from "@/lib/format"
import { useStatus } from "@/lib/queries"

/** Saved versions, newest first, loaded a page at a time. */
export function VersionsPage() {
  const { t, i18n } = useTranslation()
  const status = useStatus()
  const versions = useInfiniteQuery({
    queryKey: ["versions"],
    queryFn: ({ pageParam }) => api.versions(pageParam),
    initialPageParam: undefined as number | undefined,
    // A full page may be followed by more; the next page starts below its last version.
    getNextPageParam: (last) =>
      last.versions.length < PAGE_SIZE ? undefined : last.versions.at(-1)?.id,
  })
  if (versions.isPending) {
    return <Skeleton className="h-64" />
  }
  if (versions.isError) {
    return <ErrorAlert error={versions.error} />
  }

  const rows = versions.data.pages.flatMap((page) => page.versions)
  const inEffect = status.data?.config.version
  return (
    <>
      <PageHeader
        title={t("versions.title")}
        description={t("versions.description")}
      />
      {status.data?.config.source === "file" && (
        <Alert className="mb-4">
          <InfoIcon />
          <AlertDescription>{t("versions.fileMode")}</AlertDescription>
        </Alert>
      )}
      {rows.length === 0 ? (
        <p className="text-muted-foreground text-sm">{t("versions.empty")}</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{t("versions.id")}</TableHead>
              <TableHead>{t("versions.savedAt")}</TableHead>
              <TableHead>{t("versions.source")}</TableHead>
              <TableHead>{t("versions.comment")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((version) => (
              <TableRow key={version.id}>
                <TableCell>
                  <Link
                    to={`/versions/${version.id}`}
                    className="font-medium underline-offset-4 hover:underline"
                  >
                    #{version.id}
                  </Link>
                  {version.id === inEffect && (
                    <Badge className="ml-2">{t("versions.inEffect")}</Badge>
                  )}
                </TableCell>
                <TableCell>
                  {formatTime(version.created_at, i18n.language)}
                </TableCell>
                <TableCell>
                  <Badge variant="outline">
                    {t(`source.${version.source}`)}
                  </Badge>
                </TableCell>
                <TableCell className="text-muted-foreground">
                  {version.comment}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
      {versions.hasNextPage && (
        <Button
          variant="outline"
          className="mt-4"
          disabled={versions.isFetchingNextPage}
          onClick={() => void versions.fetchNextPage()}
        >
          {t("versions.more")}
        </Button>
      )}
    </>
  )
}
