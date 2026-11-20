{{- define "am.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Selector labels for one role: (dict "root" $ "role" "api") */}}
{{- define "am.selectorLabels" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .role }}
{{- end -}}

{{- define "am.labels" -}}
{{ include "am.selectorLabels" . }}
app.kubernetes.io/version: {{ .root.Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .root.Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .root.Chart.Name .root.Chart.Version }}
{{- end -}}

{{- define "am.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/* The role's Secret: its own, or the one the operator manages. */}}
{{- define "am.secretName" -}}
{{- $cfg := index .root.Values .role -}}
{{- $cfg.existingSecret | default (printf "%s-%s" (include "am.fullname" .root) .role) -}}
{{- end -}}

{{/* Settings every role reads, then the role's own non-empty env. */}}
{{- define "am.env" -}}
{{- $cfg := index .root.Values .role -}}
- name: AGENT_MANAGER_LOG_LEVEL
  value: {{ .root.Values.log.level | quote }}
- name: AGENT_MANAGER_LOG_FORMAT
  value: {{ .root.Values.log.format | quote }}
- name: AGENT_MANAGER_METRICS_ADDR
  value: {{ printf ":%v" .root.Values.metrics.port | quote }}
{{- with .root.Values.tracing }}
{{- if .otlpEndpoint }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .otlpEndpoint | quote }}
{{- end }}
{{- if .sampler }}
- name: OTEL_TRACES_SAMPLER
  value: {{ .sampler | quote }}
{{- end }}
{{- if .samplerArg }}
- name: OTEL_TRACES_SAMPLER_ARG
  value: {{ .samplerArg | quote }}
{{- end }}
{{- end }}
{{- range $name, $value := $cfg.env }}
{{- if $value }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
The Deployment every long-running role shares. Takes the root context, the
role, its args, and optionally an http port with its readiness path and extra
env entries.
*/}}
{{- define "am.deployment" -}}
{{- $root := .root -}}
{{- $cfg := index $root.Values .role -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "am.fullname" $root }}-{{ .role }}
  labels:
    {{- include "am.labels" . | nindent 4 }}
spec:
  replicas: {{ $cfg.replicas }}
  selector:
    matchLabels:
      {{- include "am.selectorLabels" . | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "am.labels" . | nindent 8 }}
        agent-manager.io/metrics: "true"
      {{- if not $cfg.existingSecret }}
      annotations:
        checksum/secret: {{ $cfg.secretEnv | toJson | sha256sum }}
      {{- end }}
    spec:
      serviceAccountName: {{ include "am.fullname" $root }}
      automountServiceAccountToken: false
      # A release named agent-manager would otherwise inject AGENT_MANAGER_API_PORT
      # and friends into the very prefix the binary reads its config from.
      enableServiceLinks: false
      {{- with $root.Values.imagePullSecrets }}
      imagePullSecrets:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      securityContext:
        {{- toYaml $root.Values.podSecurityContext | nindent 8 }}
      containers:
        - name: {{ .role }}
          image: {{ include "am.image" $root }}
          imagePullPolicy: {{ $root.Values.image.pullPolicy }}
          args: {{ toJson .args }}
          env:
            {{- include "am.env" . | nindent 12 }}
            {{- with .extraEnv }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          envFrom:
            - secretRef:
                name: {{ include "am.secretName" . }}
          ports:
            {{- if .port }}
            - name: http
              containerPort: {{ .port }}
            {{- end }}
            - name: metrics
              containerPort: {{ $root.Values.metrics.port }}
          livenessProbe:
            httpGet:
              path: /healthz
              port: metrics
            periodSeconds: 15
            failureThreshold: 3
          {{- if .readinessPath }}
          readinessProbe:
            httpGet:
              path: {{ .readinessPath }}
              port: http
            periodSeconds: 10
            failureThreshold: 3
          {{- end }}
          resources:
            {{- toYaml $cfg.resources | nindent 12 }}
          securityContext:
            {{- toYaml $root.Values.securityContext | nindent 12 }}
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir: {}
      {{- with $root.Values.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $root.Values.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $root.Values.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end -}}

{{/* Refuses to render a role holding a variable it must never hold. */}}
{{- define "am.forbid" -}}
{{- $cfg := index .root.Values .role -}}
{{- range $name := .names -}}
{{- if or (index (default (dict) $cfg.secretEnv) $name) (index (default (dict) $cfg.env) $name) -}}
{{- fail (printf "%s must not hold %s: that credential belongs to another role" $.role $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
