import { useSyncExternalStore } from "react"

/** Key of the Admin API token in localStorage. */
const TOKEN_KEY = "wormway.token"

/** Callbacks to run when the token changes in this tab. */
const listeners = new Set<() => void>()

/** Returns the stored token, or null when signed out. */
export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

/**
 * Stores the token until sign-out, or removes it with null. Other tabs follow through the
 * storage event.
 */
export function setToken(token: string | null): void {
  if (token === null) {
    localStorage.removeItem(TOKEN_KEY)
  } else {
    localStorage.setItem(TOKEN_KEY, token)
  }
  for (const listener of listeners) {
    listener()
  }
}

/** Calls `listener` whenever the token changes, in this tab or another one. */
function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  window.addEventListener("storage", listener)
  return () => {
    listeners.delete(listener)
    window.removeEventListener("storage", listener)
  }
}

/** The stored token, kept up to date. */
export function useToken(): string | null {
  return useSyncExternalStore(subscribe, getToken)
}
