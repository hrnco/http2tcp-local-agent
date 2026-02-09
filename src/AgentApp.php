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
		$this->connectTimeout = (int)$this->getEnvValue($env, 'HTTP2TCP_TCP_CONNECT_TIMEOUT', 300);
		$this->readTimeout = (int)$this->getEnvValue($env, 'HTTP2TCP_TCP_READ_TIMEOUT', 300);
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
		$signatureUid = $params['signature_uid'] ?? null;
		$signatureTimestamp = $params['signature_timestamp'] ?? null;
		$signatureMetadata = $params['signature_metadata'] ?? null;
		$instructions = $params['instructions'] ?? null;
		$sig = $params['sig'] ?? null;
		$kid = $params['kid'] ?? null;
		$exp = $params['exp'] ?? null;
		$nonce = $params['nonce'] ?? null;
		$pub = $params['pub'] ?? $params['pubkey'] ?? null;

		if ($exp !== null) {
			$expTimestamp = $this->parseExpiryTimestamp((string)$exp);
			if ($expTimestamp !== null && $expTimestamp < time()) {
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

		if ($signatureUid === null || $signatureTimestamp === null || $signatureMetadata === null || $instructions === null || $sig === null || $kid === null || $exp === null || $nonce === null) {
			$this->respondJson(400, [
				'status' => 'missing-params',
				'error' => 'Required params: signature_uid, signature_timestamp, signature_metadata, instructions, sig, kid, exp, nonce.',
			]);
			return;
		}

		$payload = $this->canonicalPayload(
			(string)$signatureUid,
			(string)$signatureTimestamp,
			(string)$signatureMetadata,
			(string)$instructions,
			(string)$kid,
			(string)$exp,
			(string)$nonce
		);
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
		$payloadTimeoutMs = $instructionData['payloadTimeoutMs'] ?? $instructionData['payload_timeout_ms'] ?? null;

		if (!$this->isValidDeviceHost($deviceIp)) {
			$this->respondJson(400, ['status' => 'invalid-device-ip', 'error' => 'deviceIp is required and must be a valid IP or hostname.']);
			return;
		}
		$resolvedDeviceIp = $this->resolveDeviceIp((string)$deviceIp);
		if ($resolvedDeviceIp === null) {
			$this->respondJson(400, ['status' => 'invalid-device-ip', 'error' => 'deviceIp is required and must resolve to a valid IP.']);
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
			$resolvedDeviceIp,
			(int)$devicePort,
			$payloadBase64,
			$payloadTimeoutMs
		);
		if ($tcpResult['ok'] === false) {
			$this->respondJson(502, [
				'status' => 'tcp-error',
				'error' => $tcpResult['error'],
				'device' => ['ip' => $resolvedDeviceIp, 'port' => (int)$devicePort],
			]);
			return;
		}
		$this->respondJson(200, [
			'signature_uid' => $signatureUid,
			'signature_timestamp' => $signatureTimestamp,
			'signature_metadata' => $signatureMetadata,
			'status' => 'ok',
			'paired' => true,
			'kid' => $kid,
			'device' => ['ip' => $resolvedDeviceIp, 'port' => (int)$devicePort],
			'bytes_written' => $tcpResult['bytes_written'],
			'bytes_read' => $tcpResult['bytes_read'],
			'response' => $tcpResult['response'],
		]);
	}

	private function sendCors(): void
	{
		foreach (explode('|', (string) $this->corsOrigin) as $origin) {
			$origin = trim($origin);
			if (!isset($_SERVER['HTTP_ORIGIN'])) {
				header('Access-Control-Allow-Origin: ' . $origin);
				break;
			}
			if (strcasecmp($_SERVER['HTTP_ORIGIN'], $origin) === 0) {
				header('Access-Control-Allow-Origin: ' . $origin);
				break;
			}
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

	private function canonicalPayload(string $signature_uid, string $signature_timestamp, string $signature_metadata, string $instructions, string $kid, string $exp, string $nonce): string
	{
		return 'signature_uid=' . rawurlencode($signature_uid)
			. '&signature_timestamp=' . rawurlencode($signature_timestamp)
			. '&signature_metadata=' . rawurlencode($signature_metadata)
			. '&instructions=' . rawurlencode($instructions)
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

	private function isValidDeviceHost(mixed $host): bool
	{
		if (!is_string($host)) {
			return false;
		}
		$host = trim($host);
		if ($host === '') {
			return false;
		}
		if (filter_var($host, FILTER_VALIDATE_IP)) {
			return true;
		}
		if (strcasecmp($host, 'localhost') === 0) {
			return true;
		}
		if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
			return true;
		}
		return (bool) preg_match('/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/', $host);
	}

	private function resolveDeviceIp(string $host): ?string
	{
		if (filter_var($host, FILTER_VALIDATE_IP)) {
			return $host;
		}

		$records = function_exists('dns_get_record')
			? @dns_get_record($host, DNS_A + DNS_AAAA)
			: [];
		if (is_array($records) && $records !== []) {
			foreach ($records as $record) {
				if (isset($record['ip']) && filter_var($record['ip'], FILTER_VALIDATE_IP)) {
					return $record['ip'];
				}
			}
			foreach ($records as $record) {
				if (isset($record['ipv6']) && filter_var($record['ipv6'], FILTER_VALIDATE_IP)) {
					return $record['ipv6'];
				}
			}
		}

		$ipv4 = gethostbyname($host);
		if ($ipv4 !== $host && filter_var($ipv4, FILTER_VALIDATE_IP)) {
			return $ipv4;
		}

		return null;
	}

	private function sendTcp(string $ip, int $port, string|array $payloadBase64, mixed $payloadTimeoutMs = null): array
	{
		$payloadBase64Chunks = is_array($payloadBase64) ? array_values($payloadBase64) : [$payloadBase64];
		$timeoutMsList = $this->normalizeTimeouts($payloadTimeoutMs, count($payloadBase64Chunks));
		$payloadChunks = [];
		foreach ($payloadBase64Chunks as $chunk) {
			$binary = $this->decodeBase64($chunk);
			if ($binary === null) {
				return ['ok' => false, 'error' => 'Invalid payload encoding.'];
			}
			$payloadChunks[] = $binary;
		}

		$errno = 0;
		$errstr = '';
		$fp = @fsockopen($ip, $port, $errno, $errstr, (float) $this->connectTimeout);
		if ($fp === false) {
			return ['ok' => false, 'error' => $errstr !== '' ? $errstr : 'Connection failed.'];
		}

		stream_set_blocking($fp, false);
		stream_set_timeout($fp, (int) $this->readTimeout);

		$responses = [];
		$responseByIndex = [];
		$allResponseBinary = '';
		$time = microtime(true);
		$responseSeq = 0;
		$requestDoneAt = [];
		$lastRequestBase64 = null;
		$lastRequestIndex = null;

		$drainReads = function (float $deadline, ?float $maxDeadline) use ($fp, &$responseByIndex, &$allResponseBinary, &$lastRequestBase64, &$lastRequestIndex): void {
			$lastDataAt = null;
			while (true) {
				$r = [$fp];
				$w = null;
				$e = null;

				// Wait up to 200ms for readable data (non-blocking-ish drain)
				$remaining = $deadline - microtime(true);
				if ($remaining <= 0) {
					if ($maxDeadline !== null && $lastDataAt === null && $maxDeadline > $deadline) {
						$deadline = min($maxDeadline, microtime(true) + 1.0);
						$remaining = $deadline - microtime(true);
					} else {
						break;
					}
				}

				$sec = (int) max(0, floor($remaining));
				$usec = (int) max(0, ($remaining - $sec) * 1_000_000);

				$n = @stream_select($r, $w, $e, $sec, $usec);
				if ($n === false || $n === 0) {
					if ($lastDataAt !== null && (microtime(true) - $lastDataAt) >= 2.0) {
						break;
					}
					continue;
				}

				$chunk = fread($fp, 8192);
				if ($chunk === '' || $chunk === false) {
					break;
				}

				if ($lastRequestIndex !== null) {
					$responseByIndex[$lastRequestIndex] = ($responseByIndex[$lastRequestIndex] ?? '') . $chunk;
				}
				$allResponseBinary .= $chunk;
				$lastDataAt = microtime(true);
			}
		};

		$bytesWritten = 0;

		foreach ($payloadChunks as $index => $chunk) {
			$requestBase64 = $payloadBase64Chunks[$index] ?? null;
			// Ensure the whole chunk is written (fwrite may write partially)
			$offset = 0;
			$len = strlen($chunk);

			while ($offset < $len) {
				$written = fwrite($fp, substr($chunk, $offset));
				if ($written === false || $written === 0) {
					fclose($fp);
					return ['ok' => false, 'error' => 'Failed to write payload.'];
				}

				$offset += $written;
				$bytesWritten += $written;
			}

			// Read any responses produced after this chunk
			$lastRequestBase64 = $requestBase64;
			$lastRequestIndex = $index;
			$timeoutMs = $timeoutMsList[$index] ?? null;
			$timeoutSec = $timeoutMs !== null ? max(0.001, $timeoutMs / 1000) : (float) $this->readTimeout;
			$deadline = microtime(true) + $timeoutSec;
			$drainReads($deadline, null);
			$requestDoneAt[$index] = microtime(true) - $time;
		}

		// Final drain without shutting down the socket
		$drainReads(microtime(true) + (float) $this->readTimeout, microtime(true) + 30.0);

		fclose($fp);

		foreach ($payloadBase64Chunks as $index => $requestBase64) {
			$resp = $responseByIndex[$index] ?? '';
			$responses[] = [
				'seq' => $responseSeq++,
				'time' => $requestDoneAt[$index] ?? (microtime(true) - $time),
				'phase' => 'after-send',
				'request_index' => $index,
				'request_base64' => $requestBase64,
				'response_base64' => $resp !== '' ? base64_encode($resp) : null,
			];
		}

		$bytesRead = strlen($allResponseBinary);

		return [
			'ok' => true,
			'bytes_written' => $bytesWritten,
			'bytes_read' => $bytesRead,
			'response_base64' => base64_encode($allResponseBinary),
			'response' => $responses,
		];
	}

	private function normalizeTimeouts(mixed $payloadTimeoutMs, int $count): array
	{
		if ($payloadTimeoutMs === null) {
			return [];
		}

		if (is_numeric($payloadTimeoutMs)) {
			$val = (int) $payloadTimeoutMs;
			if ($val <= 0) {
				return [];
			}
			return array_fill(0, $count, $val);
		}

		if (is_array($payloadTimeoutMs)) {
			$out = [];
			foreach (array_values($payloadTimeoutMs) as $i => $v) {
				if (!is_numeric($v)) {
					continue;
				}
				$iv = (int) $v;
				if ($iv > 0) {
					$out[$i] = $iv;
				}
			}
			return $out;
		}

		return [];
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
		$expInt = $this->parseExpiryTimestamp($exp) ?? ($now + $this->nonceTtl);
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

	private function parseExpiryTimestamp(string $exp): ?int
	{
		$exp = trim($exp);
		if ($exp === '') {
			return null;
		}
		if (ctype_digit($exp)) {
			return (int)$exp;
		}
		$timestamp = strtotime($exp);
		if ($timestamp === false || $timestamp <= 0) {
			return null;
		}
		return $timestamp;
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
