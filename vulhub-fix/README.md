# Fix for CVE-2017-11610 — Supervisor XML-RPC remote command execution

## Vulnerability

Supervisor before 3.0.1, 3.1.x before 3.1.4, 3.2.x before 3.2.4 and 3.3.x
before 3.3.3 exposes an XML-RPC interface whose method dispatcher resolves
dotted method names by walking arbitrary Python object attributes. An attacker
can therefore invoke methods that were never meant to be exposed, for example:

```
supervisor.supervisord.options.warnings.linecache.os.system
```

`xmlrpc.traverse()` performed `getattr()` for every dotted component and then
called the resolved object. This allowed traversal from the RPC namespace into
`os.system`, so a crafted XML-RPC request executed arbitrary commands as the
supervisord process (root in the container). NVD rates CVE-2017-11610
**8.8 High** (CVSS 3.0) and classifies it as CWE-276 (incorrect default
permissions) because the exposed interface was not restricted to the intended
RPC methods.

## Applied fix

`Dockerfile` installs **supervisor==3.3.3**, the release containing the
upstream fix. In 3.3.3, `xmlrpc.traverse()` was changed to:

* require exactly two dotted parts (`namespace.method`) — object traversal is
  rejected;
* reject method names beginning with `_`;
* require the resolved attribute to be a bound method.

Therefore the same request is answered with an XML-RPC `UNKNOWN_METHOD` fault
and no command is executed. `diff.patch` shows the version change.

Supervisor 3.x is Python 2 only (Python 3 support arrived in 4.0), so the
image uses `python:2.7-slim`, matching the original Vulhub environment.

## Build and run

```bash
docker compose up -d --build
```

The web interface is available at `http://127.0.0.1:9001/`.

## Verify the fix

```bash
# The same request that created /tmp/rce_proof on 3.3.2:
curl -i -X POST "http://127.0.0.1:9001/RPC2" \
     -H "Content-Type: text/xml" \
     --data-binary "@exploit.xml"
# -> HTTP 200 with an XML-RPC fault: UNKNOWN_METHOD

docker exec vulhub-fix-supervisor-1 ls -l /tmp/rce_proof
# -> No such file or directory

# Regression: interface and process management still work
curl -o /dev/null -w "%{http_code}\n" "http://127.0.0.1:9001/"     # 200
docker exec vulhub-fix-supervisor-1 supervisorctl -c /etc/supervisord.conf status
# -> demo RUNNING ...

docker exec vulhub-fix-supervisor-1 supervisord --version           # 3.3.3
```
