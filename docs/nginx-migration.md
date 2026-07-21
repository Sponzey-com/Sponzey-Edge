# Basic NGINX Migration

## NGINX

```nginx
server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Sponzey Edge MVP Model

```text
ProxyHost
  domains: app.example.com
  path_prefix: /
  upstream_url: http://127.0.0.1:3000
  https_enabled: true
  letsencrypt_enabled: true
  redirect_http_to_https: true
```

Generated model:

```text
Route
  host/path match
  service_id
  certificate_ref

Service
  upstreams
```

The Admin API validates the generated config before it sends an apply command to the core.
