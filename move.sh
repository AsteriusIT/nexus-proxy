#!/bin/bash

NEXUS_URL="http://localhost:8081"
SOURCE_REPO="npmjs"
TARGET_REPO="asterius.npm"
USER="dev"
PASS="dev"

# List all components in source repo and move them
CONTINUATION_TOKEN=""

while true; do
  URL="$NEXUS_URL/service/rest/v1/components?repository=$SOURCE_REPO"
  [ -n "$CONTINUATION_TOKEN" ] && URL="$URL&continuationToken=$CONTINUATION_TOKEN"

  RESPONSE=$(curl -s -u "$USER:$PASS" "$URL")
  CONTINUATION_TOKEN=$(echo "$RESPONSE" | jq -r '.continuationToken // empty')

  # Loop through each component
  echo "$RESPONSE" | jq -c '.items[]' | while read -r COMPONENT; do
    NAME=$(echo "$COMPONENT" | jq -r '.name')
    VERSION=$(echo "$COMPONENT" | jq -r '.version')
    DOWNLOAD_URL=$(echo "$COMPONENT" | jq -r '.assets[0].downloadUrl')

    echo "Moving $NAME@$VERSION..."

    # Download the .tgz directly (bypasses npm hooks)
    TMP_FILE="/tmp/${NAME}-${VERSION}.tgz"
    curl -s -u "$USER:$PASS" "$DOWNLOAD_URL" -o "$TMP_FILE"

    # Upload raw to target repo (no npm hooks triggered)
    curl -s -u "$USER:$PASS" \
      -X POST "$NEXUS_URL/service/rest/v1/components?repository=$TARGET_REPO" \
      -F "npm.asset=@$TMP_FILE;type=application/octet-stream"

    rm -f "$TMP_FILE"
  done

  # Exit if no more pages
  [ -z "$CONTINUATION_TOKEN" ] && break
done

echo "Done!"