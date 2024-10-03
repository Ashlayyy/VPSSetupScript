sed -i 'listen 443 ssl;/c\listen 443 ssl http2;' $1
echo "Sed command executed successfully"
echo "File $1 has been modified"
