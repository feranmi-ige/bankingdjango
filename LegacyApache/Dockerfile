# CVE-2021-41773 / CVE-2021-42013
# Apache 2.4.49 — path traversal and remote code execution via mod_cgi
# This image is intentionally vulnerable for educational use only.

FROM httpd:2.4.49

# Expose full version in Server header — lets OpenVAS identify the version
# and map it to CVE-2021-41773 (CVSS 9.8 Critical) and CVE-2021-42013
RUN echo "ServerTokens Full"     >> /usr/local/apache2/conf/httpd.conf && \
    echo "ServerSignature On"    >> /usr/local/apache2/conf/httpd.conf

# Enable mod_cgi (required for RCE vector of CVE-2021-41773)
RUN sed -i \
    's/#LoadModule cgid_module/LoadModule cgid_module/' \
    /usr/local/apache2/conf/httpd.conf || true
RUN sed -i \
    's/#LoadModule cgi_module/LoadModule cgi_module/' \
    /usr/local/apache2/conf/httpd.conf || true

# Vulnerable Directory block:
#   - Require all granted  → removes access control (needed for traversal)
#   - Options +FollowSymLinks +ExecCGI → enables symlink following and CGI exec
#   - AllowOverride All    → allows .htaccess overrides
RUN printf '\n\
<Directory />\n\
    Options +Indexes +FollowSymLinks +ExecCGI\n\
    AllowOverride All\n\
    Require all granted\n\
</Directory>\n\
\n\
<Directory "/usr/local/apache2/cgi-bin">\n\
    Options +ExecCGI\n\
    Require all granted\n\
</Directory>\n\
\n\
AddHandler cgi-script .cgi .pl .sh\n' \
>> /usr/local/apache2/conf/httpd.conf

# Copy web content and a sample CGI script
COPY htdocs/ /usr/local/apache2/htdocs/
COPY cgi-bin/ /usr/local/apache2/cgi-bin/

RUN chmod +x /usr/local/apache2/cgi-bin/*.sh 2>/dev/null || true

EXPOSE 80
CMD ["httpd-foreground"]
