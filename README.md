# running the service check


## clone the project

```
git clone git@github.com/ubirch/ubirch-service-check
```

## change into project dir, create a venv and run the script

```
cd ubirch-service-check
python3 -m venv venv3
source ./venv3/bin/activate
pip install -r requirements.txt
```

## you may want to set these environment variables

```
export UBIRCH_AUTH=<token>
export UBIRCH_ENV=dev
export UBIRCH_AUTH_MQTT="username:password"
python service-check.py
```