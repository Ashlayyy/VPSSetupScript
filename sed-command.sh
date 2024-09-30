sed '/#sslLocation/c\
> ssl_session_timeout 1d;\
> ssl_session_cache shared:MozSSL:10m;\
> ssl_session_tickets off;\
> ssl_protocols TLSv1.3;\
> ssl_prefer_server_ciphers off;\
> ssl_stapling on;\
> ssl_stapling_verify on/;' $1

echo "Sed command executed successfully"
echo "File $1 has been modified"