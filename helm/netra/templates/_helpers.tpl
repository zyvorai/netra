{{- define "netra.name" -}}netra{{- end -}}
{{- define "netra.labels" -}}
app.kubernetes.io/name: {{ include "netra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "netra.authSecretName" -}}
{{- if .Values.auth.existingSecret -}}
{{ .Values.auth.existingSecret }}
{{- else -}}
netra-auth
{{- end -}}
{{- end -}}
{{- define "netra.lokiLabels" -}}
{{- $pairs := list -}}
{{- range $k, $v := .Values.loki.labels -}}
{{- $pairs = append $pairs (printf "%s=%s" $k ($v | toString)) -}}
{{- end -}}
{{- join "," $pairs -}}
{{- end -}}
