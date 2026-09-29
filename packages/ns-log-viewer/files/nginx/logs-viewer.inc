# Nexwall consolidated log viewer - nginx wiring
# Included from /etc/nginx/conf.d/ns-ui.conf (port 9090, same TLS as ns-ui),
# only when this file exists (see /usr/sbin/ns-ui) - installed by ns-log-viewer,
# removed entirely by its "disable" action so the whole feature (including
# VictoriaLogs itself) is off unless explicitly turned on.
#
# No proxying or auth needed here: the page's own JS calls /api/logs/query,
# already proxied and JWT-authenticated by nethsecurity-api itself (see
# ns-api-server's authGroup route for /logs/query) via the existing /api/
# location in ns-ui-api.inc. This file only serves the static page.
location /logs-viewer/ {
	root /www-ns;
	index index.html;
	try_files $uri $uri/ =404;
}
