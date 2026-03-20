<?php

declare (strict_types=1);
/*
 * This file is part of fruitcake/php-cors and was originally part of asm89/stack-cors
 *
 * (c) Alexander <iam.asm89@gmail.com>
 * (c) Barryvdh <barryvdh@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
namespace Fruitcake\Cors;

use Symfony\Component\Http_Foundation\Request;
use Symfony\Component\Http_Foundation\Response;
/**
 * @phpstan-type CorsInputOptions array{
 *  'allowedOrigins'?: string[],
 *  'allowedOriginsPatterns'?: string[],
 *  'supportsCredentials'?: bool,
 *  'allowedHeaders'?: string[],
 *  'allowedMethods'?: string[],
 *  'exposedHeaders'?: string[]|false,
 *  'maxAge'?: int|bool|null,
 *  'allowed_origins'?: string[],
 *  'allowed_origins_patterns'?: string[],
 *  'supports_credentials'?: bool,
 *  'allowed_headers'?: string[],
 *  'allowed_methods'?: string[],
 *  'exposed_headers'?: string[]|false,
 *  'max_age'?: int|bool|null
 * }
 *
 */
class Cors_Service
{
    /** @var string[]  */
    private array $allowed_origins = [];
    /** @var string[] */
    private array $allowed_origins_patterns = [];
    /** @var string[] */
    private array $allowed_methods = [];
    /** @var string[] */
    private array $allowed_headers = [];
    /** @var string[] */
    private array $exposed_headers = [];
    private bool $supports_credentials = false;
    private ?int $max_age = 0;
    private bool $allow_all_origins = false;
    private bool $allow_all_methods = false;
    private bool $allow_all_headers = false;
    /**
     * @param CorsInputOptions $options
     */
    public function __construct(array $options = [])
    {
        if ($options) {
            $this->set_options($options);
        }
    }
    /**
     * @param CorsInputOptions $options
     */
    public function set_options(array $options): void
    {
        $this->allowed_origins = $options['allowedOrigins'] ?? $options['allowed_origins'] ?? $this->allowed_origins;
        $this->allowed_origins_patterns = $options['allowedOriginsPatterns'] ?? $options['allowed_origins_patterns'] ?? $this->allowed_origins_patterns;
        $this->allowed_methods = $options['allowedMethods'] ?? $options['allowed_methods'] ?? $this->allowed_methods;
        $this->allowed_headers = $options['allowedHeaders'] ?? $options['allowed_headers'] ?? $this->allowed_headers;
        $this->supports_credentials = $options['supportsCredentials'] ?? $options['supports_credentials'] ?? $this->supports_credentials;
        $max_age = $this->max_age;
        if (array_key_exists('maxAge', $options)) {
            $max_age = $options['maxAge'];
        } elseif (array_key_exists('max_age', $options)) {
            $max_age = $options['max_age'];
        }
        $this->max_age = $max_age === null ? null : (int) $max_age;
        $exposed_headers = $options['exposedHeaders'] ?? $options['exposed_headers'] ?? $this->exposed_headers;
        $this->exposed_headers = $exposed_headers === false ? [] : $exposed_headers;
        $this->normalize_options();
    }
    private function normalize_options(): void
    {
        // Normalize case
        $this->allowed_headers = array_map(strtolower(...), $this->allowed_headers);
        $this->allowed_methods = array_map(strtoupper(...), $this->allowed_methods);
        // Normalize ['*'] to true
        $this->allow_all_origins = in_array('*', $this->allowed_origins);
        $this->allow_all_headers = in_array('*', $this->allowed_headers);
        $this->allow_all_methods = in_array('*', $this->allowed_methods);
        // Combining wildcard origins with credentials is a security misconfiguration:
        // it causes the request Origin to be reflected back for any origin, bypassing
        // the intent of the wildcard restriction while also sending credentials.
        if ($this->allow_all_origins && $this->supports_credentials) {
            throw new \LogicException('CORS configuration error: "allowedOrigins: [\'*\']" cannot be combined with "supportsCredentials: true". ' . 'Listing wildcard origins with credentials enabled reflects any origin in Access-Control-Allow-Origin, ' . 'which grants every domain credential access. Use an explicit allowedOrigins list instead.');
        }
        // Transform wildcard pattern
        if (!$this->allow_all_origins) {
            foreach ($this->allowed_origins as $origin) {
                if (str_contains($origin, '*')) {
                    $this->allowed_origins_patterns[] = $this->convert_wildcard_to_pattern($origin);
                }
            }
        }
    }
    /**
     * Create a pattern for a wildcard, based on Str::is() from Laravel
     *
     * @see https://github.com/laravel/framework/blob/5.5/src/Illuminate/Support/Str.php
     */
    private function convert_wildcard_to_pattern(string $pattern): string
    {
        $pattern = preg_quote($pattern, '#');
        // Asterisks are translated into zero-or-more regular expression wildcards
        // to make it convenient to check if the strings starts with the given
        // pattern such as "*.example.com", making any string check convenient.
        $pattern = str_replace('\*', '.*', $pattern);
        return '#^' . $pattern . '\z#u';
    }
    public function is_cors_request(Request $request): bool
    {
        return $request->headers->has('Origin');
    }
    public function is_preflight_request(Request $request): bool
    {
        return $request->get_method() === 'OPTIONS' && $request->headers->has('Access-Control-Request-Method');
    }
    public function handle_preflight_request(Request $request): Response
    {
        $response = new Response();
        $response->set_status_code(204);
        return $this->add_preflight_request_headers($response, $request);
    }
    public function add_preflight_request_headers(Response $response, Request $request): Response
    {
        $this->configure_allowed_origin($response, $request);
        if ($response->headers->has('Access-Control-Allow-Origin')) {
            $this->configure_allow_credentials($response);
            $this->configure_allowed_methods($response, $request);
            $this->configure_allowed_headers($response, $request);
            $this->configure_max_age($response);
        }
        return $response;
    }
    public function is_origin_allowed(Request $request): bool
    {
        if ($this->allow_all_origins === true) {
            return true;
        }
        $origin = (string) $request->headers->get('Origin');
        if (in_array($origin, $this->allowed_origins)) {
            return true;
        }
        foreach ($this->allowed_origins_patterns as $pattern) {
            if (preg_match($pattern, $origin)) {
                return true;
            }
        }
        return false;
    }
    public function add_actual_request_headers(Response $response, Request $request): Response
    {
        $this->configure_allowed_origin($response, $request);
        if ($response->headers->has('Access-Control-Allow-Origin')) {
            $this->configure_allow_credentials($response);
            $this->configure_exposed_headers($response);
        }
        return $response;
    }
    private function configure_allowed_origin(Response $response, Request $request): void
    {
        if ($this->allow_all_origins === true && !$this->supports_credentials) {
            // Safe+cacheable, allow everything
            $response->headers->set('Access-Control-Allow-Origin', '*');
        } elseif ($this->is_single_origin_allowed()) {
            // Single origins can be safely set
            $response->headers->set('Access-Control-Allow-Origin', array_values($this->allowed_origins)[0]);
        } else {
            // For dynamic headers, set the requested Origin header when set and allowed
            if ($this->is_cors_request($request) && $this->is_origin_allowed($request)) {
                $response->headers->set('Access-Control-Allow-Origin', (string) $request->headers->get('Origin'));
            }
            $this->vary_header($response, 'Origin');
        }
    }
    private function is_single_origin_allowed(): bool
    {
        if ($this->allow_all_origins === true || count($this->allowed_origins_patterns) > 0) {
            return false;
        }
        return count($this->allowed_origins) === 1;
    }
    private function configure_allowed_methods(Response $response, Request $request): void
    {
        if ($this->allow_all_methods === true) {
            $allow_methods = strtoupper((string) $request->headers->get('Access-Control-Request-Method'));
            $this->vary_header($response, 'Access-Control-Request-Method');
        } else {
            $allow_methods = implode(', ', $this->allowed_methods);
        }
        $response->headers->set('Access-Control-Allow-Methods', $allow_methods);
    }
    private function configure_allowed_headers(Response $response, Request $request): void
    {
        if ($this->allow_all_headers === true) {
            $allow_headers = (string) $request->headers->get('Access-Control-Request-Headers');
            $this->vary_header($response, 'Access-Control-Request-Headers');
        } else {
            $allow_headers = implode(', ', $this->allowed_headers);
        }
        $response->headers->set('Access-Control-Allow-Headers', $allow_headers);
    }
    private function configure_allow_credentials(Response $response): void
    {
        if ($this->supports_credentials) {
            $response->headers->set('Access-Control-Allow-Credentials', 'true');
        }
    }
    private function configure_exposed_headers(Response $response): void
    {
        if ($this->exposed_headers) {
            $response->headers->set('Access-Control-Expose-Headers', implode(', ', $this->exposed_headers));
        }
    }
    private function configure_max_age(Response $response): void
    {
        if ($this->max_age !== null) {
            $response->headers->set('Access-Control-Max-Age', (string) $this->max_age);
        }
    }
    public function vary_header(Response $response, string $header): Response
    {
        if (!$response->headers->has('Vary')) {
            $response->headers->set('Vary', $header);
        } else {
            $vary_headers = $response->get_vary();
            if (!in_array($header, $vary_headers, true)) {
                if (count($response->headers->all('Vary')) === 1) {
                    $response->set_vary($response->headers->get('Vary') . ', ' . $header);
                } else {
                    $response->set_vary($header, false);
                }
            }
        }
        return $response;
    }
}