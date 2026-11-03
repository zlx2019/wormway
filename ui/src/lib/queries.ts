import { useQuery } from "@tanstack/react-query"

import { api } from "@/lib/api"

/** How often the status is refreshed while a page shows it, in milliseconds. */
const STATUS_INTERVAL = 5000
/** How often the traffic is refreshed: it moves by the second. */
const STATS_INTERVAL = 2000
/** How often the certificates are looked at again: they change slowly. */
const CERTIFICATES_INTERVAL = 10000

/** Status of Wormway, shared by the pages and refreshed while shown. */
export function useStatus() {
  return useQuery({
    queryKey: ["status"],
    queryFn: () => api.status(),
    refetchInterval: STATUS_INTERVAL,
  })
}

/** The traffic of the last minute, refreshed while shown. */
export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: api.stats,
    refetchInterval: STATS_INTERVAL,
  })
}

/** The health of the targets of the upstreams, refreshed while shown. */
export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: api.health,
    refetchInterval: STATUS_INTERVAL,
  })
}

/** The certificates and how they are doing, refreshed while shown. */
export function useCertificates() {
  return useQuery({
    queryKey: ["certificates"],
    queryFn: api.certificates,
    refetchInterval: CERTIFICATES_INTERVAL,
  })
}
