#!/bin/bash
echo "start memcached"
/etc/init.d/memcached restart 2>&1

# The JWT signing keys are not committed (Code Audit finding 58fa58ce). Generate
# them if this deployment has none yet (idempotent; never overwrites existing keys).
python script/generate_keys.py || exit 1

# Fail fast on secret material that has walked back into version control.
# Exit 1 = a real violation; exit 2 = no git metadata in this image, which CI covers.
python tests/test_tracked_secrets.py
gate_status=$?
if [ "$gate_status" -eq 1 ]; then
    echo "ERROR: secret material is tracked in this repository. Refusing to start."
    exit 1
fi

 echo "Makemigrations"

 while ! python manage.py makemigrations 2>&1; do
    echo "Makemigrations"
    sleep 3
 done


 echo "Migrate the Database at startup of project"

while ! python manage.py migrate  2>&1; do
   echo "Migration is in progress status"
   sleep 3
done

 echo "Django docker is fully configured successfully."

 echo "Insert record"

 while ! python script/insert.py 2>&1; do
     echo "Insert is in progress status"
     sleep 3
 done

echo "Start server"

python3 manage.py runserver 0.0.0.0:8000
sleep 3


exec "$@"
