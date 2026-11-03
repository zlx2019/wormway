import { useTranslation } from "react-i18next"

import {
  Group,
  LinesSetting,
  RowsSetting,
  Section,
  SelectSetting,
  SwitchSetting,
  TextSetting,
} from "@/components/draft"
import { useNames } from "@/components/entity"
import { FieldGroup } from "@/components/ui/field"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"

/** The form of a listener. */
export function ListenerForm() {
  const { t } = useTranslation()
  const certificates = useNames("certificates")
  return (
    <FieldGroup>
      <LinesSetting
        path="listen"
        label={t("listeners.listen")}
        hint={t("listeners.listenHint")}
        placeholder={"0.0.0.0:80\n[::]:80"}
        keep={true}
      />
      <SelectSetting
        path="protocol"
        label={t("listeners.protocol")}
        options={[{ value: "http", label: "HTTP" }]}
      />
      <Section
        path="tls"
        title={t("listeners.tls")}
        hint={t("listeners.tlsHint")}
        initial={{ certificates: [] }}
      >
        <RowsSetting
          path="tls.certificates"
          label={t("listeners.certificates")}
          hint={t("listeners.certificatesHint")}
          fresh={certificates[0] ?? ""}
          keep={true}
          render={(item, change, readOnly) => (
            // In order: the first that covers a host name is presented.
            <NativeSelect
              value={String(item)}
              className="w-full"
              disabled={readOnly}
              aria-label={t("listeners.certificates")}
              onChange={(event) => change(event.target.value)}
            >
              {[...new Set([...certificates, String(item)])].map((name) => (
                <NativeSelectOption key={name} value={name}>
                  {name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          )}
        />
        <SelectSetting
          path="tls.unknown_sni"
          label={t("listeners.unknownSni")}
          hint={t("listeners.unknownSniHint")}
          options={[
            { value: "default", label: t("listeners.sniDefault") },
            { value: "reject", label: t("listeners.sniReject") },
          ]}
          implied="default"
        />
      </Section>
      <Group title="HTTP">
        <TextSetting
          path="http.keepalive_timeout"
          label={t("listeners.keepalive")}
          hint={t("listeners.keepaliveHint")}
          placeholder="75s"
        />
        <SwitchSetting
          path="http.h2c"
          label={t("listeners.h2c")}
          hint={t("listeners.h2cHint")}
        />
      </Group>
    </FieldGroup>
  )
}
