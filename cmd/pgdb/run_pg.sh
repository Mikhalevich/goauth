docker run --rm --name test-postgres -e POSTGRES_PASSWORD=123456 -e POSTGRES_DB=auth -e POSTGRES_USER=postgres -d -p 5432:5432 postgres

