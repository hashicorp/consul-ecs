{{ .Description }}

| Field | Type | Required | Description |
| ----- | ---- | -------- | ----------- |
{{- range $key, $val := .Properties }}
{{- with $anchor := $.PropertyAnchor $key }}
| [`{{ $key }}`](#{{ $anchor }}) | `{{ index $val.Type 0 }}` | {{ $.RequiredStr $key }} | {{ $val.Description }} {{ $val.EnumStr }} |
{{- else }}
| `{{ $key }}` | `{{ index $val.Type 0 }}` | {{ $.RequiredStr $key }} | {{ $val.Description }} {{ $val.EnumStr }} |
{{- end }}
{{- end }}

