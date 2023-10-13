## !!! this project is archived here and continued at gitlab !!!


Check scripts to control if all our services are up and running nicely.
**service-check-v1.py** is responsible for Avatar- and Trackle-Service


# running the service check


Clone the project:

```
git clone git@github.com/ubirch/ubirch-service-check
```

Change into project dir, create a venv:

(make sure you use the correct version)

```
cd ubirch-service-check
python3 -m venv venv3
source ./venv3/bin/activate
pip install -r requirements-v$VERSION.txt
```

Set these environment variables:

```
#export UBIRCH_CLIENT=<client>
export UBIRCH_AUTH=<token>
export UBIRCH_ENV=dev
export UBIRCH_AUTH_MQTT="username:password"
```

Run the script:

```
python service-check.py
```
