/** English texts. The other languages must have the same keys. */
export const en = {
  app: {
    signOut: "Sign out",
    otherLanguage: "中文",
  },
  nav: {
    overview: "Overview",
    config: "Configuration",
    versions: "Versions",
  },
  common: {
    failed: "Request failed",
  },
  source: {
    db: "Database",
    file: "File",
    api: "API",
    ui: "Dashboard",
    cli: "Command line",
  },
  login: {
    title: "Sign in to zora",
    description:
      "Enter the Admin API token. zora keeps it in admin.token in its data directory, unless ZORA_ADMIN_TOKEN is set.",
    token: "Token",
    submit: "Sign in",
    wrongToken: "This token is not accepted.",
  },
  overview: {
    title: "Overview",
    version: "zora version",
    uptime: "Uptime",
    config: "Configuration",
    configVersion: "{{source}}, version {{version}}",
    configNoVersion: "{{source}}, no saved version",
    snapshot: "Snapshot",
    listeners: "Listeners",
    name: "Name",
    protocol: "Protocol",
    addresses: "Addresses",
    noListeners: "No listeners are configured.",
    instance: "Instance {{id}}",
  },
  config: {
    title: "Configuration",
    description: "The dynamic settings in effect.",
    version: "Version {{version}}",
    noVersion: "No saved version",
    fileMode:
      "These settings come from the configuration file. Edit the file and send SIGHUP to zora to change them.",
  },
  versions: {
    title: "Versions",
    description:
      "Every change is saved as a new version. A rollback saves the settings of an older version as a new one.",
    id: "Version",
    savedAt: "Saved at",
    source: "Source",
    comment: "Comment",
    inEffect: "In effect",
    empty: "No version saved yet.",
    more: "Load more",
    fileMode:
      "The settings come from the configuration file, so saved versions are not used and cannot be rolled back to.",
  },
  version: {
    title: "Version {{id}}",
    back: "All versions",
    rollback: "Roll back to this version",
    confirmTitle: "Roll back to version {{id}}?",
    confirmText:
      "The settings of version {{id}} are saved as a new version and take effect at once.",
    confirm: "Roll back",
    cancel: "Cancel",
    rolledBack: "Rolled back: version {{version}} is in effect.",
    unchanged: "These settings are already in effect.",
    conflict:
      "The configuration changed in the meantime. Check the versions and try again.",
    notFound: "Version {{id}} does not exist.",
  },
  uptime: {
    days: "{{count}}d",
    hours: "{{count}}h",
    minutes: "{{count}}m",
    seconds: "{{count}}s",
  },
  notFound: {
    title: "Page not found",
    back: "Back to the overview",
  },
}

/** Shape of the texts of one language. */
export type Messages = typeof en
