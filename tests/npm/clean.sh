# List and delete all components in a repo
NEXUS_URL="http://localhost:8081"
REPO="npmjs"
USER="admin"
PASS="ff218414-e464-4167-b47c-38678a7cc3a4"

# Delete all ASSETS (includes metadata)
TOKEN=""
while true; do
  URL="$NEXUS_URL/service/rest/v1/assets?repository=$REPO"
  [ -n "$TOKEN" ] && URL="$URL&continuationToken=$TOKEN"

  RESPONSE=$(curl -s -u "$USER:$PASS" "$URL")
  
  IDS=$(echo "$RESPONSE" | jq -r '.items[].id')
  TOKEN=$(echo "$RESPONSE" | jq -r '.continuationToken // empty')

  [ -z "$IDS" ] && break

  for ID in $IDS; do
    curl -s -u "$USER:$PASS" -X DELETE \
      "$NEXUS_URL/service/rest/v1/assets/$ID"
    echo "Deleted asset: $ID"
  done

  [ -z "$TOKEN" ] && break
done

npm cache clean --force

rm -rf node_modules
rm package-lock.json