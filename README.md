# Run containers

```bash
docker-compose up -d
```

# Stop containers

```bash
docker compose down
```

# Configure postgres

Configure pg admin at http://localhost:8080/
Add new server. Use names from .env file.
Use docker inspect to set host address of the server.
![docker1](https://github.com/user-attachments/assets/2325a270-8f2c-4c0a-b7a0-8fad5f58c229)
![docker2](https://github.com/user-attachments/assets/1fb529a8-3eba-4916-828b-62e079f25b84)

# Create required tables

sql queries are located in db_scripts directory.

# Configure MailHog

Configure MailHog at http://localhost:8025/

# Run the server

```bash
npm install
npm start
```
