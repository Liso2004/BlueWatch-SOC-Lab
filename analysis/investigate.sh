#!/bin/bash

echo "=== SECURITY INVESTIGATION ==="
echo ""

# 1. Query volume by user
echo "📊 Query Volume by User:"
curl -s -X GET "http://localhost:9200/banking-logs-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "aggs": {
    "users": {
      "terms": {
        "field": "username.keyword",
        "size": 10
      },
      "aggs": {
        "query_count": {
          "value_count": {
            "field": "username.keyword"
          }
        }
      }
    }
  }
}
' | grep -A 5 "key\|doc_count"

echo ""
echo "---"
echo ""

# 2. Timeline of jdoe's queries
echo "⏱️ jdoe Query Timeline:"
curl -s -X GET "http://localhost:9200/banking-logs-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "bool": {
      "must": [
        {"match": {"username": "jdoe"}},
        {"match": {"event": "DATABASE_QUERY"}}
      ]
    }
  },
  "size": 100,
  "sort": [{"@timestamp": "asc"}]
}
' | grep -E "@timestamp|rows_returned|event" | head -50

echo ""
echo "---"
echo ""

# 3. Search for high row counts
echo "🚨 High Volume Queries (>100 rows):"
curl -s -X GET "http://localhost:9200/banking-logs-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "range": {
      "rows_returned": {
        "gte": 100
      }
    }
  },
  "size": 20
}
' | grep -E "username|rows_returned|@timestamp"

echo ""
echo "=== Investigation Complete ==="