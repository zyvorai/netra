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
