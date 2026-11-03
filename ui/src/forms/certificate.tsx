import { useTranslation } from "react-i18next"

import {
  Choice,
  LinesSetting,
  SecretSetting,
  Section,
  SelectSetting,
  TextSetting,
  useDraft,
  useSetting,
} from "@/components/draft"
import { FieldGroup } from "@/components/ui/field"
import { without } from "@/lib/draft"

/** The form of a certificate: from files, or through ACME. */
export function CertificateForm() {
  const { t } = useTranslation()
  const { draft, update } = useDraft()
  const challenge = useSetting("acme.challenge").value
  const source = draft.acme === undefined ? "files" : "acme"
  /** Switches between files and ACME, leaving out the settings of the other. */
  function choose(next: string) {
    update((current) =>
      next === "acme"
        ? { ...without(current, ["cert", "key"]), acme: { domains: [] } }
        : without(current, ["acme"])
    )
  }
  return (
    <FieldGroup>
      <Choice
        label={t("certificates.source")}
        value={source}
        options={[
          { value: "files", label: t("certificates.files") },
          { value: "acme", label: "ACME" },
        ]}
        onChange={choose}
      />
      {source === "files" ? (
        <>
          <TextSetting
            path="cert"
            label={t("certificates.cert")}
            hint={t("certificates.certHint")}
            placeholder="certs/site.crt"
          />
          <TextSetting
            path="key"
            label={t("certificates.key")}
            placeholder="certs/site.key"
          />
        </>
      ) : (
        <>
          <LinesSetting
            path="acme.domains"
            label={t("certificates.domains")}
            hint={t("certificates.domainsHint")}
            placeholder={"example.com\nwww.example.com"}
            keep={true}
          />
          <SelectSetting
            path="acme.challenge"
            label={t("certificates.challenge")}
            hint={t("certificates.challengeHint")}
            options={[
              { value: "http-01", label: "HTTP-01" },
              { value: "dns-01", label: "DNS-01" },
            ]}
            implied="http-01"
          />
          {challenge === "dns-01" && (
            <Section
              path="acme.dns"
              title={t("certificates.dns")}
              initial={{
                provider: "cloudflare",
                api_token: { env: "CF_API_TOKEN" },
              }}
            >
              <SelectSetting
                path="acme.dns.provider"
                label={t("certificates.provider")}
                options={[{ value: "cloudflare", label: "Cloudflare" }]}
              />
              <SecretSetting
                path="acme.dns.api_token"
                label={t("certificates.apiToken")}
                hint={t("certificates.apiTokenHint")}
              />
            </Section>
          )}
        </>
      )}
    </FieldGroup>
  )
}
