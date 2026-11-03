import { useId } from "react"
import { useTranslation } from "react-i18next"

import {
  Group,
  LinesSetting,
  NumberSetting,
  RowsSetting,
  Section,
  SelectSetting,
  SwitchSetting,
  TextSetting,
  useSetting,
} from "@/components/draft"
import {
  Field,
  FieldError,
  FieldGroup,
  FieldLabel,
} from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select"
import type { Json } from "@/lib/api"
import { isObject } from "@/lib/draft"

/** The form of an upstream. */
export function UpstreamForm() {
  const { t } = useTranslation()
  const balance = useSetting("balance").value
  return (
    <FieldGroup>
      <RowsSetting
        path="targets"
        label={t("upstreams.targets")}
        hint={t("upstreams.targetsHint")}
        fresh=""
        keep={true}
        render={(item, change, readOnly) => {
          const address = isObject(item)
            ? String(item.address ?? "")
            : String(item)
          const weight =
            isObject(item) && typeof item.weight === "number"
              ? item.weight
              : undefined
          /** A target at `at` with weight `share`; weight 1 is written as the address. */
          const make = (at: string, share: number | undefined): Json =>
            share === undefined || share === 1
              ? at
              : { address: at, weight: share }
          return (
            <>
              <Input
                value={address}
                placeholder="10.0.0.1:8080"
                className="font-mono"
                disabled={readOnly}
                aria-label={t("upstreams.address")}
                onChange={(event) => change(make(event.target.value, weight))}
              />
              <Input
                type="number"
                value={weight ?? ""}
                placeholder="1"
                className="w-24"
                disabled={readOnly}
                aria-label={t("upstreams.weight")}
                onChange={(event) =>
                  change(
                    make(
                      address,
                      event.target.value === ""
                        ? undefined
                        : Number(event.target.value)
                    )
                  )
                }
              />
            </>
          )
        }}
      />
      <SelectSetting
        path="balance"
        label={t("upstreams.balance")}
        options={[
          { value: "round_robin", label: t("upstreams.roundRobin") },
          { value: "random", label: t("upstreams.random") },
          { value: "least_conn", label: t("upstreams.leastConn") },
          { value: "consistent_hash", label: t("upstreams.consistentHash") },
        ]}
        implied="round_robin"
      />
      {balance === "consistent_hash" && <HashKeySetting />}
      <SelectSetting
        path="protocol"
        label={t("upstreams.protocol")}
        hint={t("upstreams.protocolHint")}
        options={[
          { value: "h1", label: "HTTP/1.1" },
          { value: "h2", label: t("upstreams.h2") },
          { value: "h2c", label: t("upstreams.h2c") },
        ]}
        implied="h1"
      />
      <NumberSetting
        path="retries"
        label={t("upstreams.retries")}
        hint={t("upstreams.retriesHint")}
        placeholder="1"
      />
      <Group title={t("upstreams.timeouts")}>
        <TextSetting
          path="timeouts.connect"
          label={t("upstreams.connect")}
          placeholder="10s"
        />
        <TextSetting
          path="timeouts.read"
          label={t("upstreams.read")}
          placeholder="60s"
        />
        <TextSetting
          path="timeouts.write"
          label={t("upstreams.write")}
          placeholder="60s"
        />
        <TextSetting
          path="timeouts.idle"
          label={t("upstreams.idle")}
          placeholder="60s"
        />
      </Group>
      <Section
        path="health_check"
        title={t("upstreams.healthCheck")}
        hint={t("upstreams.healthCheckHint")}
        initial={{ kind: "http" }}
      >
        <SelectSetting
          path="health_check.kind"
          label={t("upstreams.checkKind")}
          options={[
            { value: "http", label: "HTTP" },
            { value: "tcp", label: "TCP" },
          ]}
        />
        <TextSetting
          path="health_check.path"
          label={t("upstreams.checkPath")}
          placeholder="/"
        />
        <TextSetting
          path="health_check.host"
          label={t("upstreams.checkHost")}
          hint={t("upstreams.checkHostHint")}
        />
        <LinesSetting
          path="health_check.status"
          label={t("upstreams.checkStatus")}
          hint={t("upstreams.checkStatusHint")}
          numbers={true}
          placeholder={"200\n204"}
        />
        <TextSetting
          path="health_check.interval"
          label={t("upstreams.interval")}
          placeholder="5s"
        />
        <TextSetting
          path="health_check.timeout"
          label={t("upstreams.checkTimeout")}
          placeholder="2s"
        />
        <NumberSetting
          path="health_check.healthy"
          label={t("upstreams.healthy")}
          placeholder="2"
        />
        <NumberSetting
          path="health_check.unhealthy"
          label={t("upstreams.unhealthy")}
          placeholder="3"
        />
      </Section>
      <Section
        path="passive"
        title={t("upstreams.passive")}
        hint={t("upstreams.passiveHint")}
        initial={{}}
      >
        <NumberSetting
          path="passive.max_fails"
          label={t("upstreams.maxFails")}
          placeholder="1"
        />
        <TextSetting
          path="passive.fail_timeout"
          label={t("upstreams.failTimeout")}
          placeholder="10s"
        />
      </Section>
      <Section
        path="tls"
        title={t("upstreams.tls")}
        hint={t("upstreams.tlsHint")}
        initial={{}}
      >
        <TextSetting
          path="tls.sni"
          label={t("upstreams.sni")}
          hint={t("upstreams.sniHint")}
        />
        <SwitchSetting
          path="tls.verify"
          label={t("upstreams.verify")}
          fallback={true}
        />
        <TextSetting
          path="tls.ca"
          label={t("upstreams.ca")}
          hint={t("upstreams.caHint")}
          placeholder="certs/ca.pem"
        />
        <TextSetting
          path="tls.cert"
          label={t("upstreams.clientCert")}
          placeholder="certs/client.crt"
        />
        <TextSetting
          path="tls.key"
          label={t("upstreams.clientKey")}
          placeholder="certs/client.key"
        />
      </Section>
    </FieldGroup>
  )
}

/** What consistent hashing hashes: the client IP address unless set, the URI, a header or a
 * cookie. */
function HashKeySetting() {
  const { t } = useTranslation()
  const id = useId()
  const { value, set, messages, readOnly } = useSetting("hash_key")
  const kind = isObject(value)
    ? "header" in value
      ? "header"
      : "cookie"
    : typeof value === "string"
      ? value
      : "client_ip"
  const name = isObject(value) ? String(value.header ?? value.cookie ?? "") : ""
  const kinds = [
    { value: "client_ip", label: t("upstreams.hashClientIp") },
    { value: "uri", label: t("upstreams.hashUri") },
    { value: "header", label: t("upstreams.hashHeader") },
    { value: "cookie", label: t("upstreams.hashCookie") },
  ]
  return (
    <Field data-invalid={messages.length > 0}>
      <FieldLabel htmlFor={id}>{t("upstreams.hashKey")}</FieldLabel>
      <div className="flex gap-2">
        <NativeSelect
          id={id}
          value={kind}
          className="shrink-0"
          disabled={readOnly}
          onChange={(event) => {
            const next = event.target.value
            set(
              next === "client_ip"
                ? undefined
                : next === "header" || next === "cookie"
                  ? { [next]: name }
                  : next
            )
          }}
        >
          {kinds.map((option) => (
            <NativeSelectOption key={option.value} value={option.value}>
              {option.label}
            </NativeSelectOption>
          ))}
        </NativeSelect>
        {(kind === "header" || kind === "cookie") && (
          <Input
            value={name}
            className="font-mono"
            disabled={readOnly}
            aria-label={t("upstreams.hashName")}
            onChange={(event) => set({ [kind]: event.target.value })}
          />
        )}
      </div>
      <FieldError errors={messages.map((message) => ({ message }))} />
    </Field>
  )
}
