import { useTranslation } from "react-i18next"

import {
  Choice,
  LinesSetting,
  SecretSetting,
  TextSetting,
  useDraft,
} from "@/components/draft"
import { FieldGroup } from "@/components/ui/field"
import { without } from "@/lib/draft"

/** The algorithms that tokens may be signed with; the HS ones use a shared secret. */
const ALGORITHMS = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "EdDSA",
]

/** The form of the settings that check JWTs. */
export function JwtForm() {
  const { t } = useTranslation()
  const { draft, update } = useDraft()
  const algorithm =
    typeof draft.algorithm === "string" ? draft.algorithm : "HS256"
  const shared = algorithm.startsWith("HS")
  /** Switches the algorithm, leaving out the kind of key that it does not use. */
  function choose(next: string) {
    update((current) => ({
      ...without(current, [next.startsWith("HS") ? "public_key" : "secret"]),
      algorithm: next,
    }))
  }
  return (
    <FieldGroup>
      <Choice
        label={t("jwt.algorithm")}
        hint={t("jwt.algorithmHint")}
        value={algorithm}
        options={ALGORITHMS.map((name) => ({ value: name, label: name }))}
        onChange={choose}
      />
      {shared ? (
        <SecretSetting
          path="secret"
          label={t("jwt.secret")}
          hint={t("jwt.secretHint")}
        />
      ) : (
        <TextSetting
          path="public_key"
          label={t("jwt.publicKey")}
          hint={t("jwt.publicKeyHint")}
          placeholder="keys/jwt.pub"
        />
      )}
      <TextSetting
        path="issuer"
        label={t("jwt.issuer")}
        hint={t("jwt.issuerHint")}
        placeholder="https://auth.example.com"
      />
      <LinesSetting
        path="audience"
        label={t("jwt.audience")}
        hint={t("jwt.audienceHint")}
      />
      <TextSetting
        path="consumer_claim"
        label={t("jwt.consumerClaim")}
        hint={t("jwt.consumerClaimHint")}
        placeholder="sub"
      />
    </FieldGroup>
  )
}
