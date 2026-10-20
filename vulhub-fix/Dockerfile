# Fixed environment for CVE-2017-12615 (Tomcat DefaultServlet PUT / JSP upload).
#
# The vulnerable environment explicitly set DefaultServlet's readonly
# initialisation parameter to "false". That override is intentionally NOT
# present here: the secure default is readonly="true", which makes the
# DefaultServlet reject PUT and DELETE requests.
#
# The base image is upgraded to Tomcat 8.5.23. That release fixes the related
# CVE-2017-12617 (a bypass of the CVE-2017-12615 remediation affecting
# 8.5.0-8.5.22), providing defence in depth even if PUT is enabled again.
FROM tomcat:8.5.23-jre8
