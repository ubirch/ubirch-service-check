#! /bin/bash
WAIT=${DELAY:-60}
echo "waiting for ${WAIT}s before doing anchor verification..."
sleep $WAIT
errors=0
while read -r line; do
  echo -n "checking \"${line}\": "
  anchors=$(curl --silent -d "$line" https://verify.${UBIRCH_ENV:-dev}.ubirch.com/api/upp/verify/record | \
    jq -r '(.anchors.upper_blockchains | length)  + (.anchors.lower_blockchains | length)')
  echo "${anchors} anchors found"
  if [ ${anchors} -lt 2 ]; then
    errors=$((errors + 1))
  fi
done < hashes.txt
if [ ${errors} -gt 0 ]; then
  echo "${errors} anchor verification errors"
  exit 1
fi