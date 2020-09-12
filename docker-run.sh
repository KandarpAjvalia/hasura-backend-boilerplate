#! /bin/bash

source ./.hasura.env

docker run -d -p 8080:8080 \
       -e HASURA_GRAPHQL_DATABASE_URL=$GRAPHQL_DATABASE_URL \
       -e HASURA_GRAPHQL_ENABLE_CONSOLE=true \
       -e HASURA_GRAPHQL_ADMIN_SECRET=$HASURA_ADMIN_SECRET \
       -e HASURA_GRAPHQL_DEV_MODE=true \
       hasura/graphql-engine:v1.3.2
