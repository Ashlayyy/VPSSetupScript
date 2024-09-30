sed '/\#sslLocation,/ {
    N
    s/#sslLocation/ssl_session_timeout 1d;\nssl_session_cache shared:MozSSL:10m;\nssl_session_tickets off;\nssl_protocols TLSv1.3;\nssl_prefer_server_ciphers off;\nssl_stapling on;\nssl_stapling_verify on/;
}' $1
echo "Sed command executed successfully"
echo "File $1 has been modified"