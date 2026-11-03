import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import type { ReactNode } from "react"
import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
  useLocation,
} from "react-router"

import { EntityEditor, type Kind, NEW } from "@/components/entity"
import { Layout } from "@/components/layout"
import { ApiError } from "@/lib/api"
import { useToken } from "@/lib/auth"
import { ConfigPage } from "@/pages/config"
import { ConsumerPage, ConsumersPage } from "@/pages/consumers"
import {
  CertificatesPage,
  certificates,
  jwt,
  ListenersPage,
  listeners,
  RoutesPage,
  routes,
  UpstreamsPage,
  upstreams,
} from "@/pages/entities"
import { LoginPage } from "@/pages/login"
import { NotFoundPage } from "@/pages/not-found"
import { OverviewPage } from "@/pages/overview"
import { VersionPage } from "@/pages/version"
import { VersionsPage } from "@/pages/versions"

/** Cache of the answers of the Admin API. */
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // An error answered by Wormway comes back when asked again; a network error may not.
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
            {entityRoutes(routes, <RoutesPage />)}
            {entityRoutes(upstreams, <UpstreamsPage />)}
            {entityRoutes(listeners, <ListenersPage />)}
            {entityRoutes(certificates, <CertificatesPage />)}
            <Route path="consumers" element={<ConsumersPage />} />
            <Route path={`consumers/${NEW}`} element={<ConsumerPage />} />
            <Route path="consumers/:name" element={<ConsumerPage />} />
            <Route path={`jwt/${NEW}`} element={<EntityEditor kind={jwt} />} />
            <Route path="jwt/:name" element={<EntityEditor kind={jwt} />} />
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

/** The pages of the entities of `kind`: `list`, a new one, and each one by name. */
function entityRoutes(kind: Kind, list: ReactNode) {
  const path = kind.path.slice(1)
  return [
    <Route key="list" path={path} element={list} />,
    <Route
      key="new"
      path={`${path}/${NEW}`}
      element={<EntityEditor kind={kind} />}
    />,
    <Route
      key="one"
      path={`${path}/:name`}
      element={<EntityEditor kind={kind} />}
    />,
  ]
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
