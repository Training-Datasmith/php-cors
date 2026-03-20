<?php

declare(strict_types=1);

require_once __DIR__ . '/../vendor/autoload.php';

use Fruitcake\Cors\Cors_Service;
use Symfony\Component\HttpFoundation\Request;

// --- Example 1: Simple setup allowing a specific origin ---
$cors = new Cors_Service([
    'allowedOrigins'   => ['https://app.example.com'],
    'allowedMethods'   => ['GET', 'POST', 'PUT', 'DELETE'],
    'allowedHeaders'   => ['Content-Type', 'Authorization'],
    'exposedHeaders'   => ['X-Custom-Header'],
    'maxAge'           => 3600,
    'supportsCredentials' => false,
]);

$request = Request::create('https://api.example.com/users', 'GET', [], [], [], [
    'HTTP_ORIGIN' => 'https://app.example.com',
]);

if ($cors->is_cors_request($request)) {
    if ($cors->is_preflight_request($request)) {
        // Handle OPTIONS preflight
        $response = $cors->handle_preflight_request($request);
        echo "Preflight response status: " . $response->getStatusCode() . "\n";
    } else {
        // Add CORS headers to a real response
        $response = new \Symfony\Component\HttpFoundation\Response('{"users":[]}', 200);
        $cors->add_actual_request_headers($response, $request);
        echo "CORS origin header: " . $response->headers->get('Access-Control-Allow-Origin') . "\n";
    }
} else {
    echo "Not a CORS request\n";
}

// --- Example 2: Allow all origins (no credentials) ---
$open_cors = new Cors_Service([
    'allowedOrigins' => ['*'],
    'allowedMethods' => ['GET'],
]);

$public_request = Request::create('https://api.example.com/status', 'GET', [], [], [], [
    'HTTP_ORIGIN' => 'https://any-site.com',
]);

$response = new \Symfony\Component\HttpFoundation\Response('{"status":"ok"}', 200);
$open_cors->add_actual_request_headers($response, $public_request);
echo "Open CORS header: " . $response->headers->get('Access-Control-Allow-Origin') . "\n"; // *

// --- Example 3: Wildcard subdomain pattern ---
$subdomain_cors = new Cors_Service([
    'allowedOrigins' => ['*.example.com'],
    'allowedMethods' => ['GET', 'POST'],
]);

echo "Subdomain allowed: " . ($subdomain_cors->is_origin_allowed(
    Request::create('/', 'GET', [], [], [], ['HTTP_ORIGIN' => 'https://api.example.com'])
) ? 'yes' : 'no') . "\n"; // yes
