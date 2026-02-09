<?php
declare(strict_types=1);

spl_autoload_register(static function (string $class): void {
	$prefix = 'App\\';
	if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
		return;
	}
	$relative = substr($class, strlen($prefix));
	$path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
	if (is_file($path)) {
		require $path;
		return;
	}
});

$envPath = __DIR__ . '/.env';
$timeout = 10;
if (array_key_exists('HTTP2TCP_TCP_READ_TIMEOUT', $_ENV)) {
    $timeout = (int)$_ENV['HTTP2TCP_TCP_READ_TIMEOUT'];
} else {
    $envTimeout = getenv('HTTP2TCP_TCP_READ_TIMEOUT');
    if ($envTimeout !== false && $envTimeout !== '') {
        $timeout = (int)$envTimeout;
    } elseif (is_file($envPath)) {
        $lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $parts = explode('=', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }
            if (trim($parts[0]) === 'HTTP2TCP_TCP_READ_TIMEOUT') {
                $timeout = (int)trim($parts[1]);
                break;
            }
        }
    }
}
if ($timeout > 0) {
    @set_time_limit($timeout);
    @ini_set('default_socket_timeout', (string)$timeout);
}

function http2tcp_send_cors()
{
	$envPath = __DIR__ . '/.env';
	$corsOrigin = $_ENV['HTTP2TCP_CORS_ALLOW_ORIGIN'] ?? getenv('HTTP2TCP_CORS_ALLOW_ORIGIN');
	if (($corsOrigin === false || $corsOrigin === null || $corsOrigin === '') && is_file($envPath)) {
		$lines = file($envPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
		foreach ($lines as $line) {
			$line = trim($line);
			if ($line === '' || str_starts_with($line, '#')) {
				continue;
			}
			$parts = explode('=', $line, 2);
			if (count($parts) !== 2) {
				continue;
			}
			if (trim($parts[0]) === 'HTTP2TCP_CORS_ALLOW_ORIGIN') {
				$corsOrigin = trim($parts[1]);
				break;
			}
		}
	}
	$corsOrigin = ($corsOrigin === false || $corsOrigin === null || $corsOrigin === '') ? '*' : (string)$corsOrigin;
	App\Cors::send($corsOrigin, $_SERVER['HTTP_ORIGIN'] ?? null);
}

function http2tcp_handle_exception($e)
{
	if (!headers_sent()) {
		http2tcp_send_cors();
		header('Content-Type: application/json; charset=utf-8');
	}
	http_response_code(500);
	$message = is_object($e) && method_exists($e, 'getMessage') ? $e->getMessage() : 'Error';
	echo json_encode(['status' => 'error', 'error' => $message], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

function http2tcp_handle_error($errno, $errstr)
{
	if (!headers_sent()) {
		http2tcp_send_cors();
		header('Content-Type: application/json; charset=utf-8');
	}
	http_response_code(500);
	echo json_encode(['status' => 'error', 'error' => $errstr], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
	return true;
}

function http2tcp_handle_shutdown()
{
	$error = error_get_last();
	if ($error === null) {
		return;
	}
	if (headers_sent()) {
		return;
	}
	http2tcp_send_cors();
	header('Content-Type: application/json; charset=utf-8');
	http_response_code(500);
	echo json_encode(['status' => 'error', 'error' => $error['message'] ?? 'Fatal error'], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
}

set_exception_handler('http2tcp_handle_exception');
set_error_handler('http2tcp_handle_error');
register_shutdown_function('http2tcp_handle_shutdown');

$app = new App\AgentApp($envPath);
$app->handle();
