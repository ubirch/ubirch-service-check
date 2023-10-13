FROM python:3

COPY ./ /build/
RUN cd /build && rm -f hashes.txt && python -m venv venv &&  . ./venv/bin/activate && pip install -q --no-cache-dir -r requirements-v2.txt && mkdir /app
WORKDIR /app
CMD /build/run_phase1.sh
# CMD python service-check-v2.py

#docker run --rm -e LOGLEVEL=${LOGLEVEL:-INFO} -e TEST_UUID=${TEST_UUID} -e TEST_KEY_EDDSA=${TEST_KEY_EDDSA} -e TEST_KEY_ECDSA=${TEST_KEY_ECDSA} -e UBIRCH_CLIENT=${UBIRCH_CLIENT} -e UBIRCH_ENV=${UBIRCH_ENV} -e UBIRCH_AUTH=${UBIRCH_AUTH} -e UBIRCH_AUTH_TYPE=${UBIRCH_AUTH_TYPE} --user `id -u`:`id -g` -v $PWD:/build -w /build python:3 /bin/bash -c "([ -f ./venv/bin/activate ] || python -m venv venv; source ./venv/bin/activate; pip install -q --no-cache-dir -r requirements-v2.txt; python service-check-v2.py)"
