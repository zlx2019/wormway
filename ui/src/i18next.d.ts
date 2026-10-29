import "i18next"

import type { Messages } from "@/locales/en"

// Text keys are checked at compile time against the English texts.
declare module "i18next" {
  interface CustomTypeOptions {
    resources: { translation: Messages }
  }
}
