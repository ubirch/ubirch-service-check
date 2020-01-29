#! /bin/bash
WAIT=${DELAY:-60}
echo "waiting for ${WAIT}s before doing anchor verification..."
sleep $WAIT
errors=0
while read -r line; do
  [ "$LOGLEVEL" == "DEBUG" ] && \
    curl --silent -d "$line" https://verify.${UBIRCH_ENV:-dev}.ubirch.com/api/upp/verify/record | jq
  anchors=$(curl --silent -d "$line" https://verify.${UBIRCH_ENV:-dev}.ubirch.com/api/upp/verify/record | \
    jq -r '(.anchors.upper_blockchains | length)  + (.anchors.lower_blockchains | length)')
  if [ "$?" != "0" ]; then
    echo -e "\e[41mchecking \"${line}\": ERROR\e[0m"
    errors=$((errors + 1))
  else
    if [ "${anchors}" == "" ]; then anchors=0; fi
    if [ ${anchors} -lt 2 ]; then
      echo -e "\e[41mchecking \"${line}\": ${anchors} anchors found\e[0m"
      errors=$((errors + 1))
    else
      echo -e "\e[32mchecking \"${line}\": ${anchors} anchors found\e[0m"
    fi
  fi
done < hashes.txt
if [ ${errors} -gt 0 ]; then
  echo "${errors} anchor verification errors"
  exit 1
fi