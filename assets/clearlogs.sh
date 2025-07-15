#!/bin/bash

DB_PATH="assets/database.db"

SQL_QUERY="DELETE FROM logs;"

sqlite3 "$DB_PATH" "$SQL_QUERY"

if [ $? -eq 0 ]; then
  echo "Successfully deleted all content from the logs table."
else
  echo "Failed to delete content from the logs table."
fi
