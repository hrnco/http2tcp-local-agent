<?php
declare(strict_types=1);

final class AgentApp
{
    private string $dataDir;
    private string $publicKeyPath;
    private string $corsOrigin;
    private int $connectTimeout;
    private int $readTimeout;
    private string $docsUrl;
    private string $nonceStorePath;
    private int $nonceTtl;

    public function __construct(string $envPath)
    {
        $env = $this->loadEnv($envPath);
        $this->dataDir = rtrim((string)$this->getEnvValue($env, 'HTTP2TCP_DATA_DIR', '/data'), '/');
        $this->publicKeyPath = $this->dataDir . '/server_public.pem';
        $this->corsOrigin = (string)$this->getEnvValue($env, 'HTTP2TCP_CORS_ALLOW_ORIGIN', '*');
        $this->connectTimeout = (int)$this->getEnvValue($env, 'HTTP2TCP_TCP_CONNECT_TIMEOUT', 2);
        $this->readTimeout = (int)$this->getEnvValue($env, 'HTTP2TCP_TCP_READ_TIMEOUT', 2);
        $this->docsUrl = (string)$this->getEnvValue($env, 'HTTP2TCP_DOCS_URL', 'https://github.com/hrnco/http2tcp-local-agent');
        $this->nonceStorePath = $this->dataDir . '/nonce_store.json';
        $this->nonceTtl = (int)$this->getEnvValue($env, 'HTTP2TCP_NONCE_TTL', 3600);
    }

    public function handle(): void
    {
        $this->sendCors();

        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            http_response_code(204);
            return;
        }

        $path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
        if ($path === '/health') {
            $this->respondJson(200, [
                'status' => 'ok',
                'paired' => is_file($this->publicKeyPath),
                'public_key_fingerprint' => is_file($this->publicKeyPath) ? $this->fingerprint($this->publicKeyPath) : null,
            ]);
            return;
        }
        if ($path === '/') {
            $this->handleRoot();
            return;
        }
        if ($path !== '/api/send') {
            $this->respondJson(404, ['status' => 'not-found']);
            return;
        }

        $params = $this->readParams();
        $instructions = $params['instructions'] ?? null;
        $sig = $params['sig'] ?? null;
        $kid = $params['kid'] ?? null;
        $exp = $params['exp'] ?? null;
        $nonce = $params['nonce'] ?? null;
        $pub = $params['pub'] ?? $params['pubkey'] ?? null;

        if ($exp !== null && ctype_digit((string)$exp)) {
            if ((int)$exp < time()) {
                $this->respondJson(401, ['status' => 'expired', 'error' => 'Signature expired.']);
                return;
            }
        }

        if (!is_dir($this->dataDir)) {
            @mkdir($this->dataDir, 0775, true);
        }

        if (!is_file($this->publicKeyPath)) {
            $pem = $this->resolvePublicKeyPem($kid, $pub);
            if ($pem === null) {
                $this->respondJson(401, [
                    'status' => 'unpaired',
                    'error' => 'Agent is not paired. Provide public key as `kid` (base64url raw key) or `pub` (PEM).',
                ]);
                return;
            }
            file_put_contents($this->publicKeyPath, $pem, LOCK_EX);
        } elseif ($pub !== null || $kid !== null) {
            $existing = trim((string)file_get_contents($this->publicKeyPath));
            $provided = $this->resolvePublicKeyPem($kid, $pub);
            if ($provided !== null && trim($provided) !== $existing) {
                $this->respondJson(401, ['status' => 'public-key-mismatch', 'error' => 'Provided public key does not match paired key.']);
                return;
            }
        }

        if ($instructions === null || $sig === null || $kid === null || $exp === null || $nonce === null) {
            $this->respondJson(400, ['status' => 'missing-params', 'error' => 'Required params: instructions, sig, kid, exp, nonce.']);
            return;
        }

        $payload = $this->canonicalPayload((string)$instructions, (string)$kid, (string)$exp, (string)$nonce);
        $sigBinary = $this->decodeSignature((string)$sig);
        if ($sigBinary === null) {
            $this->respondJson(400, ['status' => 'invalid-signature', 'error' => 'Signature must be base64url or base64.']);
            return;
        }

        if (!$this->verifySignature($this->publicKeyPath, $payload, $sigBinary)) {
            $this->respondJson(401, ['status' => 'invalid-signature', 'error' => 'Signature verification failed.']);
            return;
        }

        $nonceError = $this->checkAndStoreNonce((string)$kid, (string)$nonce, (string)$exp);
        if ($nonceError !== null) {
            $status = $nonceError === 'replay' ? 409 : 500;
            $message = $nonceError === 'replay'
                ? 'Nonce already used.'
                : 'Unable to persist nonce.';
            $this->respondJson($status, ['status' => 'nonce-error', 'error' => $message]);
            return;
        }

        $instructionData = $this->parseInstructions((string)$instructions);
        if ($instructionData === null) {
            $this->respondJson(400, ['status' => 'invalid-instructions', 'error' => 'Unable to parse instructions payload.']);
            return;
        }

        $deviceIp = $instructionData['deviceIp'] ?? null;
        $devicePort = $instructionData['devicePort'] ?? null;
        $payloadBase64 = $instructionData['payloadBase64'] ?? null;

        if (!filter_var($deviceIp, FILTER_VALIDATE_IP)) {
            $this->respondJson(400, ['status' => 'invalid-device-ip', 'error' => 'deviceIp is required and must be valid.']);
            return;
        }
        if (!is_numeric($devicePort) || (int)$devicePort < 1 || (int)$devicePort > 65535) {
            $this->respondJson(400, ['status' => 'invalid-device-port', 'error' => 'devicePort must be 1-65535.']);
            return;
        }
        if ($payloadBase64 === null) {
            $this->respondJson(400, ['status' => 'invalid-payload', 'error' => 'payloadBase64 is required.']);
            return;
        }
        if (is_string($payloadBase64)) {
            if ($payloadBase64 === '' || $this->decodeBase64($payloadBase64) === null) {
                $this->respondJson(400, ['status' => 'invalid-payload', 'error' => 'payloadBase64 must be base64 or base64url.']);
                return;
            }
        } elseif (is_array($payloadBase64)) {
            if ($payloadBase64 === []) {
                $this->respondJson(400, ['status' => 'invalid-payload', 'error' => 'payloadBase64 array must not be empty.']);
                return;
            }
            foreach ($payloadBase64 as $chunk) {
                if (!is_string($chunk) || $chunk === '' || $this->decodeBase64($chunk) === null) {
                    $this->respondJson(400, ['status' => 'invalid-payload', 'error' => 'payloadBase64 array items must be base64 or base64url strings.']);
                    return;
                }
            }
        } else {
            $this->respondJson(400, ['status' => 'invalid-payload', 'error' => 'payloadBase64 must be a base64 string or array of base64 strings.']);
            return;
        }

        $tcpResult = $this->sendTcp(
            (string)$deviceIp,
            (int)$devicePort,
            $payloadBase64
        );
        if ($tcpResult['ok'] === false) {
            $this->respondJson(502, [
                'status' => 'tcp-error',
                'error' => $tcpResult['error'],
                'device' => ['ip' => $deviceIp, 'port' => (int)$devicePort],
            ]);
            return;
        }

        $this->respondJson(200, [
            'status' => 'ok',
            'paired' => true,
            'kid' => $kid,
            'device' => ['ip' => $deviceIp, 'port' => (int)$devicePort],
            'bytes_written' => $tcpResult['bytes_written'],
            'bytes_read' => $tcpResult['bytes_read'],
            'response_base64' => $tcpResult['response_base64'],
        ]);
    }

    private function sendCors(): void
    {
        foreach (explode('|', (string) $this->corsOrigin) as $origin) {
            header('Access-Control-Allow-Origin: ' . trim($origin));
        }
        header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
        header('Access-Control-Allow-Headers: Content-Type, X-Custom-Header');
        if ($this->corsOrigin !== '*') {
            header('Access-Control-Allow-Credentials: true');
        }
    }

    private function respondJson(int $status, array $payload): void
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    private function readParams(): array
    {
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        if (stripos($contentType, 'application/json') !== false) {
            $raw = file_get_contents('php://input');
            $decoded = json_decode($raw ?: '', true);
            return is_array($decoded) ? $decoded : [];
        }
        return array_merge($_GET ?? [], $_POST ?? []);
    }

    private function normalizePem(string $input): ?string
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

    private function resolvePublicKeyPem(?string $kid, ?string $pub): ?string
    {
        if ($pub !== null) {
            $pem = $this->normalizePem($pub);
            if ($pem !== null) {
                return $pem;
            }
        }

        if ($kid !== null) {
            $raw = $this->base64urlDecode($kid);
            if ($raw !== null && strlen($raw) === 32) {
                return $this->ed25519RawToPem($raw);
            }
        }

        return null;
    }

    private function base64urlDecode(string $value): ?string
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

    private function ed25519RawToPem(string $rawKey): string
    {
        $der = hex2bin('302a300506032b6570032100') . $rawKey;
        $b64 = chunk_split(base64_encode($der), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
    }

    private function fingerprint(string $publicKeyPath): string
    {
        $data = file_get_contents($publicKeyPath);
        return hash('sha256', $data ?: '');
    }

    private function canonicalPayload(string $instructions, string $kid, string $exp, string $nonce): string
    {
        return 'instructions=' . rawurlencode($instructions)
            . '&kid=' . rawurlencode($kid)
            . '&exp=' . rawurlencode($exp)
            . '&nonce=' . rawurlencode($nonce);
    }

    private function decodeSignature(string $sig): ?string
    {
        $binary = base64_decode($sig, true);
        if ($binary !== false) {
            return $binary;
        }

        $binary = $this->base64urlDecode($sig);
        if ($binary !== null) {
            return $binary;
        }

        return null;
    }

    private function verifySignature(string $publicKeyPath, string $payload, string $signature): bool
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

    private function parseInstructions(string $instructions): ?array
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

        $decodedBase64Url = $this->base64urlDecode($trimmed);
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

    private function sendTcp(string $ip, int $port, string|array $payloadBase64): array
    {
        $payloadChunks = [];
        if (is_array($payloadBase64)) {
            foreach ($payloadBase64 as $chunk) {
                $binary = $this->decodeBase64($chunk);
                if ($binary === null) {
                    return ['ok' => false, 'error' => 'Invalid payload encoding.'];
                }
                $payloadChunks[] = $binary;
            }
        } else {
            $binary = $this->decodeBase64($payloadBase64);
            if ($binary === null) {
                return ['ok' => false, 'error' => 'Invalid payload encoding.'];
            }
            $payloadChunks[] = $binary;
        }

        $errno = 0;
        $errstr = '';
        $fp = @fsockopen($ip, $port, $errno, $errstr, (float)$this->connectTimeout);
        if ($fp === false) {
            return ['ok' => false, 'error' => $errstr !== '' ? $errstr : 'Connection failed.'];
        }

        stream_set_timeout($fp, $this->readTimeout);
        $bytesWritten = 0;
        foreach ($payloadChunks as $chunk) {
            $written = fwrite($fp, $chunk);
            if ($written === false) {
                fclose($fp);
                return ['ok' => false, 'error' => 'Failed to write payload.'];
            }
            $bytesWritten += $written;
        }

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
            'bytes_written' => $bytesWritten,
            'bytes_read' => strlen($response),
            'response_base64' => base64_encode($response),
        ];
    }

    private function decodeBase64(string $data): ?string
    {
        $decoded = base64_decode($data, true);
        if ($decoded !== false) {
            return $decoded;
        }
        return $this->base64urlDecode($data);
    }

    private function checkAndStoreNonce(string $kid, string $nonce, string $exp): ?string
    {
        if ($this->nonceTtl <= 0) {
            return null;
        }

        $now = time();
        $expInt = ctype_digit($exp) ? (int)$exp : ($now + $this->nonceTtl);
        $expiresAt = min($expInt, $now + $this->nonceTtl);

        $fp = @fopen($this->nonceStorePath, 'c+');
        if ($fp === false) {
            return 'store-unavailable';
        }

        if (!flock($fp, LOCK_EX)) {
            fclose($fp);
            return 'store-unavailable';
        }

        $contents = stream_get_contents($fp);
        $store = json_decode($contents ?: '', true);
        if (!is_array($store)) {
            $store = [];
        }

        foreach ($store as $key => $expiry) {
            if (!is_int($expiry)) {
                if (is_string($expiry) && ctype_digit($expiry)) {
                    $expiry = (int)$expiry;
                } else {
                    unset($store[$key]);
                    continue;
                }
            }
            if ($expiry <= $now) {
                unset($store[$key]);
            }
        }

        $key = hash('sha256', $kid . '|' . $nonce);
        if (isset($store[$key]) && (int)$store[$key] > $now) {
            flock($fp, LOCK_UN);
            fclose($fp);
            return 'replay';
        }

        $store[$key] = $expiresAt;

        ftruncate($fp, 0);
        rewind($fp);
        fwrite($fp, json_encode($store, JSON_UNESCAPED_SLASHES));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);

        return null;
    }

    private function loadEnv(string $path): array
    {
        if (!is_file($path)) {
            return [];
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [];
        $env = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }
            $parts = explode('=', $line, 2);
            if (count($parts) !== 2) {
                continue;
            }
            $key = trim($parts[0]);
            $value = trim($parts[1]);
            $env[$key] = $value;
        }
        return $env;
    }

    private function getEnvValue(array $fileEnv, string $key, $default)
    {
        if (array_key_exists($key, $_ENV)) {
            return $_ENV[$key];
        }
        if (array_key_exists($key, $fileEnv)) {
            return $fileEnv[$key];
        }
        return $default;
    }

    private function handleRoot(): void
    {
        $paired = is_file($this->publicKeyPath);
        $docsUrl = $this->docsUrl;
        $statusText = $paired ? 'paired' : 'not paired';
        $statusColor = $paired ? '#1a7f37' : '#d1242f';

        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html><head><meta charset="utf-8"><title>http2tcp-local-agent</title></head><body>';
        echo '<div style="font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; font-size: 18px; line-height: 1.5; color: #111; padding: 12px;">';
        echo '<div style="margin: 0 0 6px 0;">Agent is <span style="color: #1a7f37; font-weight: 700;">active</span>.</div>';
        echo '<div style="margin: 0 0 6px 0;">Agent is <span style="color: ' . $statusColor . '; font-weight: 700;">' . $statusText . '</span>.</div>';
        if (!$paired) {
            echo '<div style="margin: 10px 0 6px 0;">Server is running. For pairing instructions, see:</div>';
            echo '<a href="' . htmlspecialchars($docsUrl, ENT_QUOTES, 'UTF-8') . '" style="color: #2f6feb; font-weight: 600; text-decoration: underline; text-underline-offset: 2px;">' . htmlspecialchars($docsUrl, ENT_QUOTES, 'UTF-8') . '</a>';
        }
        echo '</div></body></html>';
    }
}
