# Fix for CVE-2017-12615 — Tomcat DefaultServlet PUT / JSP upload

## Vulnerability

The vulnerable Vulhub environment (`vulhub/tomcat/CVE-2017-12615`) runs Apache
Tomcat 8.5.19 and injects this insecure `DefaultServlet` setting into
`conf/web.xml`:

```xml
<init-param>
  <param-name>readonly</param-name>
  <param-value>false</param-value>
</init-param>
```

With `readonly=false`, the `DefaultServlet` mapped to `/` accepts HTTP PUT.
An unauthenticated attacker can upload a JSP file despite the servlet's
`.jsp` suffix check by appending a trailing `/` to the request path
(`PUT /shell.jsp/`). The operating system strips the trailing separator and
writes `shell.jsp` into the web root; a later GET compiles and executes it,
resulting in remote code execution as the Tomcat user (root in this image).

## Applied fix

1. **Version upgrade.** The base image is `tomcat:8.5.23-jre8`. Tomcat 8.5.23
   fixes CVE-2017-12617, the bypass of the CVE-2017-12615 remediation
   (affected 8.5.0–8.5.22).
2. **Configuration fix.** The Dockerfile no longer inserts `readonly=false`,
   so `DefaultServlet` keeps its secure default `readonly=true` and rejects
   PUT/DELETE. This addresses the vulnerable configuration independently of
   the version upgrade.

See `diff.patch` for the exact change.

## Build and run

```bash
docker compose up -d --build
```

The application is available at `http://127.0.0.1:8080/`.

## Verify the fix

```bash
# Same attack as the vulnerable environment: must be rejected
curl -i -X PUT "http://127.0.0.1:8080/shell.jsp/" \
     --data-binary "@shell.jsp" \
     -H "Content-Type: application/octet-stream"
# -> HTTP/1.1 403 Forbidden

# No webshell was written
curl -o /dev/null -w "%{http_code}\n" \
     "http://127.0.0.1:8080/shell.jsp?cmd=id"
# -> 404

# Regression: normal functionality still works
curl -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8080/"
# -> 200
curl -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:8080/docs/"
# -> 200
```

Expected server version and configuration:

```
Apache Tomcat/8.5.23
no readonly init-param (secure default true)
```
