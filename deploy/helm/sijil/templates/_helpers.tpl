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

{{/* repository@digest when a digest is set, else repository:tag. No default from the chart's appVersion: each
     image is pinned on its own, so the ledger can be upgraded before the guard (OPERATOR_GUIDE_M2.md §14). */}}
{{- define "sijil.image" -}}
{{- if .image.digest }}{{ .image.repository }}@{{ .image.digest }}
{{- else }}{{ .image.repository }}:{{ required (printf "image.%s.tag (or image.%s.digest) is required: the release tag, e.g. v1.2.0" .name .name) .image.tag }}
{{- end }}
{{- end }}

{{/* The adapter sidecar, its key-copy init container and their volumes: what examples/agent-sidecar.yaml shows
     for an agent of your own. */}}
{{- define "sijil.guardContainer" -}}
- name: {{ .name }}
  image: {{ include "sijil.image" (dict "image" .root.Values.image.guard "name" "guard") | quote }}
  imagePullPolicy: {{ .root.Values.image.pullPolicy }}
  args: {{ toJson .args }}
  env:
    - name: SIJIL_TOKEN
      valueFrom: {secretKeyRef: {name: {{ include "sijil.secretName" .root }}, key: agent-token}}
    - name: SIJIL_TOOLS_TOKEN
      valueFrom: {secretKeyRef: {name: {{ include "sijil.secretName" .root }}, key: tools-token}}
  securityContext: {{ toJson .root.Values.securityContext }}
  resources: {{ toJson .root.Values.guard.resources }}
  {{- if and .probe .root.Values.guard.probes.enabled }}
  {{- $probe := dict "exec" (dict "command" (list "python" "-c" "import json, urllib.request as u; assert json.load(u.urlopen('http://127.0.0.1:8090/_sijil/healthz', timeout=3))['ok'] is True")) }}
  readinessProbe: {{ merge (dict "periodSeconds" 10 "timeoutSeconds" 5) $probe | toJson }}
  livenessProbe: {{ merge (dict "initialDelaySeconds" 10 "periodSeconds" 30 "timeoutSeconds" 5 "failureThreshold" 4) $probe | toJson }}
  {{- end }}
  volumeMounts:
    - {name: guard-config, mountPath: /config, readOnly: true}
    - {name: rulepack, mountPath: /rulepack, readOnly: true}
    - {name: guard-state, mountPath: /state}
{{- end }}
