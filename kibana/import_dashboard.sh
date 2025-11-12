#!/bin/bash
# Kibana Dashboard Import Script for ELK 8.15

KIBANA_HOST="${KIBANA_HOST:-localhost}"
KIBANA_PORT="${KIBANA_PORT:-5601}"
KIBANA_URL="http://${KIBANA_HOST}:${KIBANA_PORT}"
DASHBOARD_FILE="dashboard_kibana.ndjson"

# Optional: Set credentials if authentication is enabled
KIBANA_USER="${KIBANA_USER:-}"
KIBANA_PASS="${KIBANA_PASS:-}"

echo "========================================"
echo "Kibana Dashboard Import"
echo "========================================"
echo "Kibana URL: ${KIBANA_URL}"
echo "Dashboard file: ${DASHBOARD_FILE}"
echo ""

# Check if Kibana is accessible
echo "Checking Kibana accessibility..."
if command -v curl &> /dev/null; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${KIBANA_URL}/api/status")
    if [ "$HTTP_CODE" == "200" ] || [ "$HTTP_CODE" == "401" ]; then
        echo "✓ Kibana is accessible"
    else
        echo "✗ Cannot reach Kibana at ${KIBANA_URL}"
        echo "  HTTP Status: ${HTTP_CODE}"
        echo "  Please check that Kibana is running and accessible."
        exit 1
    fi
else
    echo "⚠ curl not found, skipping connectivity check"
fi

echo ""

# Build authentication parameters
AUTH_PARAM=""
if [ -n "${KIBANA_USER}" ] && [ -n "${KIBANA_PASS}" ]; then
    AUTH_PARAM="-u ${KIBANA_USER}:${KIBANA_PASS}"
    echo "Using authentication: ${KIBANA_USER}"
fi

# Import dashboard
echo "Importing dashboard..."

if [ ! -f "${DASHBOARD_FILE}" ]; then
    echo "✗ Dashboard file not found: ${DASHBOARD_FILE}"
    exit 1
fi

RESPONSE=$(curl -s -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    ${AUTH_PARAM} \
    --form file=@"${DASHBOARD_FILE}")

echo "${RESPONSE}" | grep -q '"success":true'

if [ $? -eq 0 ]; then
    echo "✓ Dashboard imported successfully!"
    echo ""
    echo "Access the dashboard at:"
    echo "${KIBANA_URL}/app/dashboards"
    echo ""
    echo "Look for: 'Honeypot IDS Dashboard'"
else
    echo "✗ Import failed or partial"
    echo ""
    echo "Response:"
    echo "${RESPONSE}" | python3 -m json.tool 2>/dev/null || echo "${RESPONSE}"
    echo ""
    echo "========================================"
    echo "Manual Import Instructions"
    echo "========================================"
    echo "1. Open Kibana: ${KIBANA_URL}"
    echo "2. Navigate to: Management → Stack Management → Saved Objects"
    echo "3. Click 'Import' button"
    echo "4. Select file: ${DASHBOARD_FILE}"
    echo "5. Check 'Automatically overwrite conflicts'"
    echo "6. Click 'Import'"
    echo ""
fi

echo "========================================"
echo ""
