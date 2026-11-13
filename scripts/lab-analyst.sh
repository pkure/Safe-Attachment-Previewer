#!/usr/bin/env bash
# hal-id: #HAL-20261113-0024-PK-L1
# LAB ONLY: create a licensed, non-admin test analyst for the cloud v2 demo (run by a tenant admin, signed in with az).
#   scripts/lab-analyst.sh <domain>            e.g. contoso.onmicrosoft.com
# The temporary password goes to the macOS Keychain ("<domain> analyst1 (temp)"), never to the screen or a file.
# The analyst must change it (and register MFA) at first sign-in.
set -euo pipefail
DOMAIN="${1:?usage: $0 <domain>}"
UPN="analyst1@$DOMAIN"
G=https://graph.microsoft.com/v1.0

if az rest --method get --url "$G/users/$UPN" --query id -o tsv >/dev/null 2>&1; then
  echo "$UPN already exists"
else
  PW="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)!a9"
  security add-generic-password -U -a analyst1 -s "$DOMAIN analyst1 (temp)" -w "$PW"
  body=$(printf '{"accountEnabled":true,"displayName":"Analyst One (lab)","mailNickname":"analyst1","userPrincipalName":"%s","usageLocation":"US","passwordProfile":{"forceChangePasswordNextSignIn":true,"password":"%s"}}' "$UPN" "$PW")
  unset PW
  az rest --method post --url "$G/users" --headers Content-Type=application/json --body "$body" --query id -o tsv >/dev/null
  unset body
  echo "created $UPN (temp password in Keychain: \"$DOMAIN analyst1 (temp)\")"
fi

SKU=$(az rest --method get --url "$G/subscribedSkus" --query "value[?prepaidUnits.enabled > consumedUnits] | [0].skuId" -o tsv)
[ -n "$SKU" ] || { echo "no free license seat"; exit 1; }
az rest --method post --url "$G/users/$UPN/assignLicense" --headers Content-Type=application/json \
  --body "{\"addLicenses\":[{\"skuId\":\"$SKU\"}],\"removeLicenses\":[]}" --query userPrincipalName -o tsv
echo "licensed. The mailbox appears in a few minutes; then run: pwsh scripts/exchange-setup-v2.ps1 -Domain $DOMAIN"
