#!/bin/bash

# Traffic generator for Security Blueprint API
# Generates mix of successful requests and errors to test Grafana dashboard

API_URL="http://localhost:8000"
INTERVAL=2  # seconds between requests

echo "🚀 Starting traffic generator for $API_URL"
echo "📊 This will generate a mix of successful and error responses"
echo "Press Ctrl+C to stop"
echo ""

# Counter for tracking
success_count=0
error_count=0

while true; do
    # Generate 3 successful requests
    echo "✅ Sending successful requests..."
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/" 
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/health"
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/"
    success_count=$((success_count + 3))
    
    sleep $INTERVAL
    
    # Generate 1-2 errors (404s from non-existent endpoints)
    echo "❌ Sending error requests..."
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/nonexistent"
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/invalid/path"
    error_count=$((error_count + 2))
    
    sleep $INTERVAL
    
    # Generate another successful request
    curl -s -o /dev/null -w "Status: %{http_code}\n" "$API_URL/"
    success_count=$((success_count + 1))
    
    # Display summary
    echo "📈 Total - Success: $success_count | Errors: $error_count | Error Rate: $((error_count * 100 / (success_count + error_count)))%"
    echo "---"
    
    sleep $INTERVAL
done
