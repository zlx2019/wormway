import { useQueryClient } from "@tanstack/react-query"
import { cn } from "cn"
import { LogOutIcon } from "lucide-react"
import { useTranslation } from "react-i18next"
import { NavLink, Outlet, useLocation } from "react-router"

import { LanguageSwitch } from "@/components/language-switch"
import { Button } from "@/components/ui/button"
import { setToken } from "@/lib/auth"

/** Pages in the navigation, with the key of their title and other paths that belong to them. */
const pages = [
  { to: "/", title: "nav.overview", end: true, also: [] },
  { to: "/routes", title: "nav.routes", end: false, also: [] },
  { to: "/upstreams", title: "nav.upstreams", end: false, also: [] },
  { to: "/listeners", title: "nav.listeners", end: false, also: [] },
  { to: "/certificates", title: "nav.certificates", end: false, also: [] },
  { to: "/consumers", title: "nav.consumers", end: false, also: ["/jwt"] },
  { to: "/config", title: "nav.config", end: false, also: [] },
  { to: "/versions", title: "nav.versions", end: false, also: [] },
] as const

/** Frame of the signed-in pages: navigation, language switch and sign-out. */
export function Layout() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const { pathname } = useLocation()

  /** Forgets the token and everything loaded with it. */
  function signOut() {
    setToken(null)
    queryClient.clear()
  }

  return (
    <div className="min-h-svh">
      <header className="border-b">
        <div className="mx-auto flex h-14 max-w-5xl items-center gap-6 px-4">
          <span className="font-semibold">Wormway</span>
          <nav className="flex gap-4 text-sm">
            {pages.map((page) => (
              <NavLink
                key={page.to}
                to={page.to}
                end={page.end}
                className={({ isActive }) =>
                  cn(
                    "text-muted-foreground transition-colors hover:text-foreground",
                    (isActive ||
                      page.also.some((path: string) =>
                        pathname.startsWith(path)
                      )) &&
                      "font-medium text-foreground"
                  )
                }
              >
                {t(page.title)}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto flex gap-2">
            <LanguageSwitch />
            <Button variant="outline" size="sm" onClick={signOut}>
              <LogOutIcon />
              {t("app.signOut")}
            </Button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-5xl px-4 py-6">
        <Outlet />
      </main>
    </div>
  )
}
