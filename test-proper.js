#!/usr/bin/env node

const http = require('http');

// Test with a proper date query
async function testProperESQuery() {
    console.log('=== Testing ElasticSearch with Proper Date Query ===\n');
    
    const requestBody = JSON.stringify({
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "2025-08-18T00:00:00.000Z",
                    "lte": "2025-08-18T23:59:59.999Z"
                }
            }
        },
        "size": 5
    });
    
    const options = {
        hostname: process.env.PROXY_HOST || 'localhost',
        port: process.env.PROXY_PORT || 9201,
        path: '/logstash-fluentbit-2025.08.18/_search',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(requestBody)
        }
    };
    
    console.log('Request options:', options);
    console.log('Request body:', requestBody);
    console.log();
    
    const req = http.request(options, (res) => {
        console.log('Response status:', res.statusCode);
        console.log('Response headers:', res.headers);
        console.log();
        
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Response body:');
            try {
                const jsonResponse = JSON.parse(data);
                console.log(JSON.stringify(jsonResponse, null, 2));
            } catch (e) {
                console.log(data);
            }
        });
    });
    
    req.on('error', (e) => {
        console.error('Request error:', e.message);
    });
    
    req.write(requestBody);
    req.end();
}

// Test with match_all query (safest)
async function testMatchAllQuery() {
    console.log('\n=== Testing ElasticSearch with Match All Query ===\n');
    
    const requestBody = JSON.stringify({
        "query": {
            "match_all": {}
        },
        "size": 2
    });
    
    const options = {
        hostname: process.env.PROXY_HOST || 'localhost',
        port: process.env.PROXY_PORT || 9201,
        path: '/logstash-fluentbit-2025.08.18/_search',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(requestBody)
        }
    };
    
    console.log('Match All Request options:', options);
    console.log('Match All Request body:', requestBody);
    console.log();
    
    const req = http.request(options, (res) => {
        console.log('Match All Response status:', res.statusCode);
        console.log('Match All Response headers:', res.headers);
        console.log();
        
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Match All Response body:');
            try {
                const jsonResponse = JSON.parse(data);
                // Just show metadata, not all results
                const result = {
                    took: jsonResponse.took,
                    timed_out: jsonResponse.timed_out,
                    hits: {
                        total: jsonResponse.hits?.total,
                        max_score: jsonResponse.hits?.max_score,
                        hits_count: jsonResponse.hits?.hits?.length,
                        first_hit_fields: jsonResponse.hits?.hits?.[0] ? Object.keys(jsonResponse.hits.hits[0]._source || {}) : []
                    }
                };
                console.log(JSON.stringify(result, null, 2));
            } catch (e) {
                console.log(data);
            }
        });
    });
    
    req.on('error', (e) => {
        console.error('Match All Request error:', e.message);
    });
    
    req.write(requestBody);
    req.end();
}

// Test index mapping to see field types
async function testIndexMapping() {
    console.log('\n=== Testing Index Mapping ===\n');
    
    const options = {
        hostname: process.env.PROXY_HOST || 'localhost',
        port: process.env.PROXY_PORT || 9201,
        path: '/logstash-fluentbit-2025.08.18/_mapping',
        method: 'GET'
    };
    
    console.log('Mapping Request options:', options);
    console.log();
    
    const req = http.request(options, (res) => {
        console.log('Mapping Response status:', res.statusCode);
        console.log();
        
        let data = '';
        res.on('data', (chunk) => {
            data += chunk;
        });
        
        res.on('end', () => {
            console.log('Index Mapping (first 1000 chars):');
            try {
                const jsonResponse = JSON.parse(data);
                const mappingStr = JSON.stringify(jsonResponse, null, 2);
                console.log(mappingStr.substring(0, 1000) + (mappingStr.length > 1000 ? '...[truncated]' : ''));
            } catch (e) {
                console.log(data.substring(0, 1000));
            }
        });
    });
    
    req.on('error', (e) => {
        console.error('Mapping Request error:', e.message);
    });
    
    req.end();
}

console.log('Testing AWS ES Proxy with proper queries...');
console.log('Use environment variables PROXY_HOST and PROXY_PORT to customize target');
console.log('Example: PROXY_HOST=localhost PROXY_PORT=9201 node test-proper.js\n');

// Run tests sequentially
testIndexMapping();
setTimeout(testMatchAllQuery, 2000);
setTimeout(testProperESQuery, 4000);
