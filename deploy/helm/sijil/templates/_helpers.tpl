{{- define "sijil.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}{{ .Release.Name | trunc 63 | trimSuffix "-" }}{{ else }}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}{{ end }}
{{- end }}

{{- define "sijil.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{- define "sijil.ledgerUrl" -}}
http://{{ include "sijil.fullname" . }}-ledger:{{ .Values.ledger.service.port }}
{{- end }}

{{- define "sijil.secretName" -}}
{{ .Values.secrets.existingSecret | default (printf "%s-tokens" (include "sijil.fullname" .)) }}
{{- end }}

{{- define "sijil.image" -}}
{{ .image.repository }}:{{ .image.tag | default .root.Chart.AppVersion }}
{{- end }}

{{/* The adapter sidecar, its key-copy init container and their volumes: what examples/agent-sidecar.yaml shows
     for an agent of your own. */}}
{{- define "sijil.guardContainer" -}}
- name: {{ .name }}
  image: {{ include "sijil.image" (dict "image" .root.Values.image.guard "root" .root) }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  args: {{ toJson .args }}
  env:
    - name: SIJIL_TOKEN
      valueFrom: {secretKeyRef: {name: {{ include "sijil.secretName" .root }}, key: agent-token}}
    - name: SIJIL_TOOLS_TOKEN
      valueFrom: {secretKeyRef: {name: {{ include "sijil.secretName" .root }}, key: tools-token}}
  securityContext: {{ toJson .root.Values.securityContext }}
  resources: {{ toJson .root.Values.guard.resources }}
  volumeMounts:
    - {name: guard-config, mountPath: /config, readOnly: true}
    - {name: rulepack, mountPath: /rulepack, readOnly: true}
    - {name: guard-state, mountPath: /state}
{{- end }}
