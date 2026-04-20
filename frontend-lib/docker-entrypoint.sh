#!/bin/sh
set -e

# Inject runtime env vars into config.js so the browser can read them
cat > /usr/share/nginx/html/config.js <<EOF
window.UPPASS_API_URL = "${UPPASS_API_URL:-http://localhost:8000}";
EOF

# Replace PORT placeholder in nginx config, then start nginx
envsubst '${PORT}' < /etc/nginx/conf.d/default.conf > /tmp/default.conf
cp /tmp/default.conf /etc/nginx/conf.d/default.conf

exec nginx -g "daemon off;"
