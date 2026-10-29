import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import type { ReactNode } from "react"
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router"

import { Layout } from "@/components/layout"
import { ApiError } from "@/lib/api"
import { useToken } from "@/lib/auth"
import { ConfigPage } from "@/pages/config"
import { LoginPage } from "@/pages/login"
import { NotFoundPage } from "@/pages/not-found"
import { OverviewPage } from "@/pages/overview"
import { VersionPage } from "@/pages/version"
import { VersionsPage } from "@/pages/versions"

/** Cache of the answers of the Admin API. */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // An error answered by zora comes back when asked again; a network error may not.
      retry: (failures, error) => !(error instanceof ApiError) && failures < 2,
    },
  },
})

/** The dashboard: every page but the sign-in needs the token. */
export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter basename={import.meta.env.BASE_URL}>
        <Routes>
          <Route path="login" element={<LoginPage />} />
          <Route
            element={
              <RequireToken>
                <Layout />
              </RequireToken>
            }
          >
            <Route index element={<OverviewPage />} />
            <Route path="config" element={<ConfigPage />} />
            <Route path="versions" element={<VersionsPage />} />
            <Route path="versions/:id" element={<VersionPage />} />
            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  )
}

/** Shows `children` when signed in; otherwise the sign-in page, which comes back here. */
function RequireToken({ children }: { children: ReactNode }) {
  const token = useToken()
  const location = useLocation()
  if (token === null) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }
  return children
}
