#!/bin/bash

DB_USER=""
DB_PASSWORD=""
DB_NAME=""
DB_HOST="localhost"

SQL_QUERY="DELETE FROM logs;"

mysql -u $DB_USER -p$DB_PASSWORD -h $DB_HOST $DB_NAME -e "$SQL_QUERY"

if [ $? -eq 0 ]; then
  echo "Successfully deleted all content from the logs table."
else
  echo "Failed to delete content from the logs table."
fi
