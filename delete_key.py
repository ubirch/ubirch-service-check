import requests

NEO4J_URL="http://neo4j-core-node-0-yyjy7ntrgtqv2.westeurope.cloudapp.azure.com:7474/db/data/transaction/commit"
NEO4J_AUTH="neo4j:jq94ErtbR04Bt3YSqUX5FT"

uuid = "55424952-3c71-bf88-1524-3c71bf881524"

r = requests.post(NEO4J_URL, json={"statements": [{
    "statement": "MATCH (n:PublicKey) WHERE n.infoHwDeviceId='{}' RETURN n;".format(uuid),
}]}, auth=tuple(NEO4J_AUTH.split(":")))
print(f"{r.status_code:03d} {r.content}")

r = requests.post(NEO4J_URL, json={"statements": [{
    "statement": "MATCH (n:PublicKey) WHERE n.infoHwDeviceId='{}' DELETE n;".format(uuid),
}]}, auth=tuple(NEO4J_AUTH.split(":")))
print(f"{r.status_code:03d} {r.content}")
