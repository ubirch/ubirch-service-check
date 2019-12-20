#! /bin/bash
echo "waiting for 60s before doing anchor verification..."
sleep 60
errors=0
while read -r line; do
  echo -n "checking \"${line}\": "
  anchors=$(curl --silent -d "$line" https://verify.${UBIRCH_ENV:-dev}.ubirch.com/api/upp/verify/record | \
    jq -r '(.anchors.upper_blockchains | length)  + (.anchors.lower_blockchains | length)')
  if [ ${anchors} -ge 2 ]; then
    echo "${anchors} anchors found"
  else
    echo "only ${anchors} anchors found"
    errors=$((errors + 1))
  fi
done
if [ ${errors} -gt 0 ]; then
  echo "${errors} anchor verification errors"
  exit 1
fi