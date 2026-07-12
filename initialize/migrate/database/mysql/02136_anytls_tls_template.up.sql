UPDATE `subscribe_application`
SET `subscribe_template` = REPLACE(
  `subscribe_template`,
  '  type: anytls\n  server: {{ $server }}',
  '  type: anytls\n  tls: true\n  server: {{ $server }}'
)
WHERE `subscribe_template` LIKE '%type: anytls%'
  AND `subscribe_template` NOT LIKE '%type: anytls\n  tls: true%';

UPDATE `subscribe_application`
SET `subscribe_template` = REPLACE(
  `subscribe_template`,
  '{{ $proxy.Name }} = anytls, {{ $server }}, {{ $proxy.Port }}, password={{ $password }}',
  '{{ $proxy.Name }} = anytls, {{ $server }}, {{ $proxy.Port }}, password={{ $password }}{{- if eq $proxy.Security "tls" }}, tls=true{{- end }}'
)
WHERE `subscribe_template` LIKE '%{{ $proxy.Name }} = anytls%'
  AND `subscribe_template` NOT LIKE '%tls=true%';

UPDATE `subscribe_application`
SET `subscribe_template` = REPLACE(
  `subscribe_template`,
  'anytls://{{ $password }}@{{ $server }}:{{ $proxy.Port }}?{{ join "&" $params }}#{{ $proxy.Name }}',
  'anytls://{{ $password }}@{{ $server }}:{{ $proxy.Port }}/?{{- if ne (default "" $proxy.SNI) "" }}sni={{ $proxy.SNI }}&{{- end }}{{- if $proxy.AllowInsecure }}insecure=1&{{- end }}{{ $common }}#{{ $proxy.Name | urlquery }}'
)
WHERE `subscribe_template` LIKE '%anytls://{{ $password }}@%'
  AND `subscribe_template` LIKE '%join "&" $params%';
