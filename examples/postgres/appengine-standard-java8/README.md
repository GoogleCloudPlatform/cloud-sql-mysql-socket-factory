# PostgreSQL sample for Google App Engine for Java 8
This sample demonstrates how to use [PostgreSql](https://cloud.google.com/sql/) on Google App
Engine standard for Java 8.

## Setup

* If you haven't already, Download and initialize the [Cloud SDK](https://cloud.google.com/sdk/):

    `gcloud init`

* If you haven't already, Create an App Engine app within the current Google Cloud Project:

    `gcloud app create`

* If you haven't already, Setup [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials):

    `gcloud auth application-default login`


* [Create an instance](https://cloud.google.com/sql/docs/postgres/create-instance)

* [Create a Database](https://cloud.google.com/sql/docs/postgres/create-manage-databases)

* [Create a user](https://cloud.google.com/sql/docs/postgres/create-manage-users)

* Note **Instance connection name** under **Overview > properties**  
`Project:Region:Instance`

## Running locally
When running locally, the SocketFactory can use either the `cloud_sql_proxy` or it can get a certificate
from Cloud SQL and connect directly.

### cloud_sql_proxy

* `./cloud_sql_proxy -dir=/cloudsql &`
* `export GAE_RUNTIME=java8`
* Follow steps for Connecting directly below

### Connect directly 
```bash
$ mvn clean appengine:run -DINSTANCE_CONNECTION_NAME=instanceConnectionName -Duser=root -Dpassword=myPassowrd -Ddatabase=myDatabase
```

## Deploying

```bash
$ mvn clean appengine:deploy -DINSTANCE_CONNECTION_NAME=instanceConnectionName -Duser=root
-Dpassword=myPassword -Ddatabase=myDatabase
```


## Cleaning up

* [Delete your Instance](https://cloud.google.com/sql/docs/postgres/delete-instance)