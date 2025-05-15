#!/usr/bin/env bash
set -eux

container_name="${CONTAINER_NAME}"
password="${OPENGAUSS_PASSWORD}"
port=${PORT}
sql_file=${SQL_FILE}
mounted_dir=${MOUNT_DIR_IN_CONTAINER}


if [ -t 0 ]; then
  TTY_FLAG="-t"
else
  TTY_FLAG=""
fi

# verify_sql_user_connection: verify that the username and password created using the SQL file can connect to the database.
function verify_sql_created_user_connection() {
  docker exec -i ${TTY_FLAG} "${container_name}" bash -c "su - omm -c 'gsql -U gaussdbgo_md5 -p ${port} -W${password} -d gaussdbgo_test -c \"select version(); show server_version;\"'"
}

# Replace password in SQL file
sudo sed -i "s/'{{OPENGAUSS_PASSWORD}}'/'${password}'/" "${mounted_dir}/${sql_file}"

# Initialize database
docker exec -i ${TTY_FLAG} "${container_name}" bash -c "su - omm -c 'gsql -U omm -c \"CREATE DATABASE gaussdbgo_test;\" -f ${mounted_dir}/${sql_file}'"

# Verify user connection
echo "Verifying created user can connect..."
verify_sql_created_user_connection

echo "Database initialization completed successfully."
exit 0