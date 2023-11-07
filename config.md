# IMAGESCANER CONFIGMAP 


| Variable Name       | Value                                  | Description                   |
|---------------------|----------------------------------------|-------------------------------|
| CLAIR_ADDR          | clair-dcd.devtroncd:6060               | For connecting to Clair if it's enabled |
| CLIENT_ID           | client-2                               | Client ID                        |
| NATS_SERVER_HOST    | nats://devtron-nats.devtroncd:4222    | For connecting to NATS         |
| PG_LOG_QUERY        | "false"                                | PostgreSQL Query Logging (false to disable) |
| PG_ADDR             | postgresql-postgresql.devtroncd        | PostgreSQL Server Address       |
| PG_DATABASE         | orchestrator                           | PostgreSQL Database Name       |
| PG_PORT             | "5432"                                 | PostgreSQL Port Number         |
| PG_USER             | postgres                               | PostgreSQL User Name           |

