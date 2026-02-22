#!/bin/bash

LOCK_FILE="${1:-package-lock.json}"

if [[ ! -f "$LOCK_FILE" ]]; then
  echo "File not found: $LOCK_FILE"
  exit 1
fi

# Extract all package names from packages keys (skip root "")
packages=$(jq -r '.packages | keys[]' "$LOCK_FILE" | grep '^node_modules/' | sed 's|^node_modules/||')

while IFS= read -r package; do
  # Build URL based on scoped or not
  if [[ "$package" == @* ]]; then
    # scoped: @scope/name
    scope=$(echo "$package" | cut -d'/' -f1 | sed 's/@//')
    name=$(echo "$package" | cut -d'/' -f2)
    url="http://localhost:8000/npm/${scope}/${name}"
  else
    url="http://localhost:8000/npm/${package}"
  fi

  echo "PATCH $url"
  curl -s -o /dev/null -w "%{http_code}" -X PATCH "$url"
  echo ""
done <<< "$packages"