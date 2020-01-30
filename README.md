#Aby uruchomić należy pobrać docker-compose:
sudo wget "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -O /usr/bin/docker-compose
sudo chmod +x /usr/bin/docker-compose

#Aplikację uruchamia się komendą:
docker-compose up --build