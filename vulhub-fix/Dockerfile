# Fixed environment for CVE-2017-11610 (Supervisor XML-RPC object traversal).
#
# Supervisor 3.3.3 fixes the vulnerability by restricting XML-RPC method
# resolution to exactly one namespace and one method, and by requiring the
# resolved attribute to be a bound method. Arbitrary attribute traversal
# (e.g. supervisord.options.warnings.linecache.os.system) is rejected.
FROM python:2.7-slim

RUN pip install --no-cache-dir supervisor==3.3.3

COPY supervisord.conf /etc/supervisord.conf

EXPOSE 9001

CMD ["supervisord", "-c", "/etc/supervisord.conf"]
