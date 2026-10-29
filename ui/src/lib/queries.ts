import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api"

/** How often the status is refreshed while a page shows it, in milliseconds. */
const STATUS_INTERVAL = 5000

/** Status of zora, shared by the pages and refreshed while shown. */
export function useStatus() {
  return useQuery({
    queryKey: ["status"],
    queryFn: () => api.status(),
    refetchInterval: STATUS_INTERVAL,
  })
}
