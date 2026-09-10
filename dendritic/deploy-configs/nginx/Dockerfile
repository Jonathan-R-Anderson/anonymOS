FROM nginx:1.27-alpine

RUN apk add --no-cache openssl

RUN mkdir -p /etc/nginx/tls
# Permissive defaults for the domain-guard includes so nginx.conf always loads
# even before the entrypoint regenerates them from DOMAIN.
RUN mkdir -p /etc/nginx/domain-guard \
    && printf 'server_name _;\n' > /etc/nginx/domain-guard/allowed-host.conf \
    && : > /etc/nginx/domain-guard/default-deny.conf
COPY docker-entrypoint.sh /docker-entrypoint.d/40-generate-self-signed-cert.sh
RUN chmod +x /docker-entrypoint.d/40-generate-self-signed-cert.sh
