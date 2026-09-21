{{- define "zanskar.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "zanskar.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "zanskar.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "zanskar.labels" -}}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
app.kubernetes.io/name: {{ include "zanskar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "zanskar.selectorLabels" -}}
app.kubernetes.io/name: {{ include "zanskar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: gateway
{{- end -}}

{{- define "zanskar.guacdSelectorLabels" -}}
app.kubernetes.io/name: {{ include "zanskar.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: guacd
{{- end -}}

{{- define "zanskar.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "zanskar.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "zanskar.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{- define "zanskar.guacdAddr" -}}
{{- printf "%s-guacd:4822" (include "zanskar.fullname" .) -}}
{{- end -}}

{{/* Environment shared by the gateway and the migrate job. */}}
{{- define "zanskar.env" -}}
- name: ZANSKAR_MASTER_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: ZANSKAR_MASTER_KEY
- name: ZANSKAR_DB_DSN
  valueFrom:
    secretKeyRef:
      name: {{ .Values.existingSecret }}
      key: ZANSKAR_DB_DSN
{{- range .Values.config.extraEnv }}
- name: {{ .name }}
  value: {{ .value | quote }}
{{- end }}
{{- end -}}

{{- define "zanskar.envFrom" -}}
- configMapRef:
    name: {{ include "zanskar.fullname" . }}
{{- range .Values.config.extraEnvFrom }}
- {{ toYaml . | nindent 2 | trim }}
{{- end }}
{{- end -}}

{{- define "zanskar.podSecurityContext" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "zanskar.containerSecurityContext" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities:
  drop: ["ALL"]
{{- end -}}
