<?php

/**
 * Simple API Test Script
 * This script demonstrates how to use the Laravel Authentication API
 */

$baseUrl = 'http://localhost:8000/api';

// Test data
$testUser = [
    'name' => 'Test User',
    'email' => 'test@example.com',
    'password' => 'password123',
    'password_confirmation' => 'password123'
];

echo "=== Laravel Authentication API Test ===\n\n";

// Function to make HTTP requests
function makeRequest($url, $method = 'GET', $data = null, $headers = []) {
    $ch = curl_init();
    
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
    
    if ($data) {
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        $headers[] = 'Content-Type: application/json';
    }
    
    if ($headers) {
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    }
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    return [
        'code' => $httpCode,
        'response' => json_decode($response, true)
    ];
}

// 1. Test User Registration
echo "1. Testing User Registration...\n";
$signupResponse = makeRequest($baseUrl . '/signup', 'POST', $testUser);

if ($signupResponse['code'] === 201) {
    echo "✅ Registration successful!\n";
    echo "User ID: " . $signupResponse['response']['data']['user']['id'] . "\n";
    echo "Message: " . $signupResponse['response']['message'] . "\n\n";
} else {
    echo "❌ Registration failed!\n";
    echo "Status Code: " . $signupResponse['code'] . "\n";
    echo "Response: " . json_encode($signupResponse['response'], JSON_PRETTY_PRINT) . "\n\n";
}

// 2. Test Login (should fail without email verification)
echo "2. Testing Login (should fail without email verification)...\n";
$loginData = [
    'email' => $testUser['email'],
    'password' => $testUser['password']
];

$loginResponse = makeRequest($baseUrl . '/login', 'POST', $loginData);

if ($loginResponse['code'] === 403) {
    echo "✅ Login correctly blocked (email not verified)!\n";
    echo "Message: " . $loginResponse['response']['message'] . "\n\n";
} else {
    echo "❌ Unexpected response!\n";
    echo "Status Code: " . $loginResponse['code'] . "\n";
    echo "Response: " . json_encode($loginResponse['response'], JSON_PRETTY_PRINT) . "\n\n";
}

// 3. Test Invalid Login
echo "3. Testing Invalid Login...\n";
$invalidLoginData = [
    'email' => 'invalid@example.com',
    'password' => 'wrongpassword'
];

$invalidLoginResponse = makeRequest($baseUrl . '/login', 'POST', $invalidLoginData);

if ($invalidLoginResponse['code'] === 401) {
    echo "✅ Invalid login correctly rejected!\n";
    echo "Message: " . $invalidLoginResponse['response']['message'] . "\n\n";
} else {
    echo "❌ Unexpected response!\n";
    echo "Status Code: " . $invalidLoginResponse['code'] . "\n";
    echo "Response: " . json_encode($invalidLoginResponse['response'], JSON_PRETTY_PRINT) . "\n\n";
}

echo "=== Test Complete ===\n";
echo "\nTo complete the test:\n";
echo "1. Check your email for verification link\n";
echo "2. Click the verification link\n";
echo "3. Try logging in again\n";
echo "4. Use the returned token for authenticated requests\n";
