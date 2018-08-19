# running the service check


Clone the project:

```
git clone git@github.com/ubirch/ubirch-service-check
```

Change into project dir, create a venv:

```
cd ubirch-service-check
python3 -m venv venv3
source ./venv3/bin/activate
pip install -r requirements.txt
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