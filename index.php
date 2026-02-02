<?php

declare(strict_types=1);

$dataDir = '/data';
$publicKeyPath = $dataDir . '/server_public.pem';

if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0775, true);
}

$corsOrigin = getenv('HTTP2TCP_CORS_ALLOW_ORIGIN') ?: '*';
header('Access-Control-Allow-Origin: ' . $corsOrigin);
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Custom-Header');
if ($corsOrigin !== '*') {
    header('Access-Control-Allow-Credentials: true');
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

header('Content-Type: application/json; charset=utf-8');

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

if ($path === '/' || $path === '/health') {
    respond(200, [
        'status' => 'ok',
        'paired' => file_exists($publicKeyPath),
        'public_key_fingerprint' => file_exists($publicKeyPath) ? fingerprint($publicKeyPath) : null,
    ]);
}

if ($path !== '/api/send') {
    respond(404, ['status' => 'not-found']);
}

$params = read_params();
$instructions = $params['instructions'] ?? null;
$sig = $params['sig'] ?? null;
$kid = $params['kid'] ?? null;
$exp = $params['exp'] ?? null;
$nonce = $params['nonce'] ?? null;
$pub = $params['pub'] ?? $params['pubkey'] ?? null;

if ($exp !== null && ctype_digit((string)$exp)) {
    if ((int)$exp < time()) {
        respond(401, ['status' => 'expired', 'error' => 'Signature expired.']);
    }
}

if (!file_exists($publicKeyPath)) {
    $pem = resolve_public_key_pem($kid, $pub);
    if ($pem === null) {
        respond(401, [
            'status' => 'unpaired',
            'error' => 'Agent is not paired. Provide public key as `kid` (base64url raw key) or `pub` (PEM).',
        ]);
    }
    file_put_contents($publicKeyPath, $pem, LOCK_EX);
} elseif ($pub !== null || $kid !== null) {
    $existing = trim((string)file_get_contents($publicKeyPath));
    $provided = resolve_public_key_pem($kid, $pub);
    if ($provided !== null && trim($provided) !== $existing) {
        respond(401, ['status' => 'public-key-mismatch', 'error' => 'Provided public key does not match paired key.']);
    }
}

if ($instructions === null || $sig === null || $kid === null || $exp === null || $nonce === null) {
    respond(400, ['status' => 'missing-params', 'error' => 'Required params: instructions, sig, kid, exp, nonce.']);
}

$payload = canonical_payload((string)$instructions, (string)$kid, (string)$exp, (string)$nonce);
$sigBinary = decode_signature((string)$sig);
if ($sigBinary === null) {
    respond(400, ['status' => 'invalid-signature', 'error' => 'Signature must be base64 (or hex).']);
}

if (!verify_signature($publicKeyPath, $payload, $sigBinary)) {
    respond(401, ['status' => 'invalid-signature', 'error' => 'Signature verification failed.']);
}

$instructionData = parse_instructions((string)$instructions);
if ($instructionData === null) {
    respond(400, ['status' => 'invalid-instructions', 'error' => 'Unable to parse instructions payload.']);
}

$deviceIp = $instructionData['deviceIp'] ?? null;
$devicePort = $instructionData['devicePort'] ?? null;
$payloadHex = $instructionData['payloadHex'] ?? null;

if (!filter_var($deviceIp, FILTER_VALIDATE_IP)) {
    respond(400, ['status' => 'invalid-device-ip', 'error' => 'deviceIp is required and must be valid.']);
}
if (!is_numeric($devicePort) || (int)$devicePort < 1 || (int)$devicePort > 65535) {
    respond(400, ['status' => 'invalid-device-port', 'error' => 'devicePort must be 1-65535.']);
}
if (!is_string($payloadHex) || $payloadHex === '' || !ctype_xdigit($payloadHex)) {
    respond(400, ['status' => 'invalid-payload', 'error' => 'payloadHex must be a hex string.']);
}

$tcpResult = send_tcp($deviceIp, (int)$devicePort, $payloadHex);
if ($tcpResult['ok'] === false) {
    respond(502, [
        'status' => 'tcp-error',
        'error' => $tcpResult['error'],
        'device' => ['ip' => $deviceIp, 'port' => (int)$devicePort],
    ]);
}

respond(200, [
    'status' => 'ok',
    'paired' => true,
    'kid' => $kid,
    'device' => ['ip' => $deviceIp, 'port' => (int)$devicePort],
    'bytes_written' => $tcpResult['bytes_written'],
    'bytes_read' => $tcpResult['bytes_read'],
    'response_hex' => $tcpResult['response_hex'],
    'response_base64' => $tcpResult['response_base64'],
]);

function respond(int $status, array $payload): void
{
    http_response_code($status);
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function read_params(): array
{
    $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
    if (stripos($contentType, 'application/json') !== false) {
        $raw = file_get_contents('php://input');
        $decoded = json_decode($raw ?: '', true);
        return is_array($decoded) ? $decoded : [];
    }

    return array_merge($_GET ?? [], $_POST ?? []);
}

function normalize_pem(string $input): ?string
{
    $trimmed = trim($input);
    if (str_contains($trimmed, 'BEGIN PUBLIC KEY')) {
        return $trimmed . "\n";
    }

    $decoded = base64_decode($trimmed, true);
    if ($decoded !== false && str_contains($decoded, 'BEGIN PUBLIC KEY')) {
        return trim($decoded) . "\n";
    }

    return null;
}

function resolve_public_key_pem(?string $kid, ?string $pub): ?string
{
    if ($pub !== null) {
        $pem = normalize_pem($pub);
        if ($pem !== null) {
            return $pem;
        }
    }

    if ($kid !== null) {
        $raw = base64url_decode($kid);
        if ($raw !== null && strlen($raw) === 32) {
            return ed25519_raw_to_pem($raw);
        }
    }

    return null;
}

function base64url_decode(string $value): ?string
{
    $value = trim($value);
    if ($value === '') {
        return null;
    }
    $padded = strtr($value, '-_', '+/');
    $padLen = 4 - (strlen($padded) % 4);
    if ($padLen < 4) {
        $padded .= str_repeat('=', $padLen);
    }
    $decoded = base64_decode($padded, true);
    return $decoded === false ? null : $decoded;
}

function ed25519_raw_to_pem(string $rawKey): string
{
    // Ed25519 SubjectPublicKeyInfo prefix: 302a300506032b6570032100
    $der = hex2bin('302a300506032b6570032100') . $rawKey;
    $b64 = chunk_split(base64_encode($der), 64, "\n");
    return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
}

function fingerprint(string $publicKeyPath): string
{
    $data = file_get_contents($publicKeyPath);
    return hash('sha256', $data ?: '');
}

function canonical_payload(string $instructions, string $kid, string $exp, string $nonce): string
{
    return 'instructions=' . rawurlencode($instructions)
        . '&kid=' . rawurlencode($kid)
        . '&exp=' . rawurlencode($exp)
        . '&nonce=' . rawurlencode($nonce);
}

function decode_signature(string $sig): ?string
{
    $binary = base64_decode($sig, true);
    if ($binary !== false) {
        return $binary;
    }

    $binary = base64url_decode($sig);
    if ($binary !== null) {
        return $binary;
    }

    if (ctype_xdigit($sig) && strlen($sig) % 2 === 0) {
        $hex = hex2bin($sig);
        return $hex === false ? null : $hex;
    }

    return null;
}

function verify_signature(string $publicKeyPath, string $payload, string $signature): bool
{
    $payloadFile = tempnam(sys_get_temp_dir(), 'h2t_msg_');
    $sigFile = tempnam(sys_get_temp_dir(), 'h2t_sig_');

    if ($payloadFile === false || $sigFile === false) {
        return false;
    }

    file_put_contents($payloadFile, $payload, LOCK_EX);
    file_put_contents($sigFile, $signature, LOCK_EX);

    $cmd = sprintf(
        'openssl pkeyutl -verify -rawin -pubin -inkey %s -sigfile %s -in %s 2>/dev/null',
        escapeshellarg($publicKeyPath),
        escapeshellarg($sigFile),
        escapeshellarg($payloadFile)
    );

    exec($cmd, $output, $code);

    @unlink($payloadFile);
    @unlink($sigFile);

    return $code === 0;
}

function parse_instructions(string $instructions): ?array
{
    $trimmed = trim($instructions);
    if ($trimmed === '') {
        return null;
    }

    $decodedJson = json_decode($trimmed, true);
    if (is_array($decodedJson)) {
        return $decodedJson;
    }

    $decodedBase64 = base64_decode($trimmed, true);
    if ($decodedBase64 !== false) {
        $decodedJson = json_decode($decodedBase64, true);
        if (is_array($decodedJson)) {
            return $decodedJson;
        }
    }

    $decodedBase64Url = base64url_decode($trimmed);
    if ($decodedBase64Url !== null) {
        $decodedJson = json_decode($decodedBase64Url, true);
        if (is_array($decodedJson)) {
            return $decodedJson;
        }
    }

    $parsed = [];
    parse_str($trimmed, $parsed);
    return $parsed !== [] ? $parsed : null;
}

function send_tcp(string $ip, int $port, string $payloadHex): array
{
    $payload = hex2bin($payloadHex);
    if ($payload === false) {
        return ['ok' => false, 'error' => 'Invalid payload hex.'];
    }

    $errno = 0;
    $errstr = '';
    $fp = @fsockopen($ip, $port, $errno, $errstr, 2.0);
    if ($fp === false) {
        return ['ok' => false, 'error' => $errstr !== '' ? $errstr : 'Connection failed.'];
    }

    stream_set_timeout($fp, 2);
    $bytesWritten = fwrite($fp, $payload);

    $response = '';
    while (!feof($fp)) {
        $chunk = fread($fp, 8192);
        if ($chunk === '' || $chunk === false) {
            $meta = stream_get_meta_data($fp);
            if (!empty($meta['timed_out'])) {
                break;
            }
            if ($chunk === false) {
                break;
            }
        }
        $response .= $chunk;
    }
    fclose($fp);

    return [
        'ok' => true,
        'bytes_written' => $bytesWritten === false ? 0 : $bytesWritten,
        'bytes_read' => strlen($response),
        'response_hex' => bin2hex($response),
        'response_base64' => base64_encode($response),
    ];
}
