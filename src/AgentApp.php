<?php
declare(strict_types=1);

namespace App;

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
	private bool $multiPairingEnabled;
	private Services\SignatureService $signatureService;
	private Services\KeyStore $keyStore;
	private Services\NonceStore $nonceStore;
	private Services\InstructionValidator $instructionValidator;
	private Services\TcpClient $tcpClient;
	private ResponseCheckers\ResponseCheckerFactory $responseCheckerFactory;
	private Services\Base64Service $base64Service;
	private Services\InstructionParser $instructionParser;

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
		$this->multiPairingEnabled = $this->getEnvBool($env, 'HTTP2TCP_MULTI_PAIRING', false);
		$this->base64Service = new Services\Base64Service();
		$keyParser = new Services\Ed25519KeyParser();
		$this->signatureService = new Services\SignatureService($this->base64Service, $keyParser);
		$this->keyStore = new Services\KeyStore($this->dataDir, $this->publicKeyPath, $this->base64Service, $keyParser);
		$this->nonceStore = new Services\NonceStore($this->nonceStorePath, $this->nonceTtl);
		$this->instructionValidator = new Services\InstructionValidator($this->readTimeout, $this->base64Service);
		$this->instructionParser = new Services\InstructionParser($this->base64Service);
		$this->responseCheckerFactory = new ResponseCheckers\ResponseCheckerFactory();
		$this->tcpClient = new Services\TcpClient($this->connectTimeout, $this->readTimeout, $this->responseCheckerFactory, $this->base64Service);
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
				'paired' => $this->keyStore->hasAnyKey(),
				'public_key_fingerprint' => $this->keyStore->defaultFingerprint(),
				'multi_pairing' => $this->multiPairingEnabled,
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

		$this->handleSend($this->readParams());
	}

	private function handleSend(array $params): void
	{
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
			$expTimestamp = $this->signatureService->parseExpiryTimestamp((string)$exp);
			if ($expTimestamp !== null && $expTimestamp < time()) {
				$this->respondJson(401, ['status' => 'expired', 'error' => 'Signature expired.']);
				return;
			}
		}

		$pairing = $this->keyStore->ensurePaired($kid, $pub);
		if (($pairing['ok'] ?? false) !== true) {
			$this->respondJson((int)($pairing['status'] ?? 401), [
				'status' => $pairing['code'] ?? 'pairing-error',
				'error' => $pairing['error'] ?? 'Pairing failed.',
			]);
			return;
		}

		if ($signatureUid === null || $signatureTimestamp === null || $signatureMetadata === null || $instructions === null || $sig === null || $kid === null || $exp === null || $nonce === null) {
			$this->respondJson(400, [
				'status' => 'missing-params',
				'error' => 'Required params: signature_uid, signature_timestamp, signature_metadata, instructions, sig, kid, exp, nonce.',
			]);
			return;
		}

		$payload = $this->signatureService->canonicalPayload(
			(string)$signatureUid,
			(string)$signatureTimestamp,
			(string)$signatureMetadata,
			(string)$instructions,
			(string)$kid,
			(string)$exp,
			(string)$nonce
		);
		$sigBinary = $this->signatureService->decodeSignature((string)$sig);
		if ($sigBinary === null) {
			$this->respondJson(400, ['status' => 'invalid-signature', 'error' => 'Signature must be base64url or base64.']);
			return;
		}

		$publicKeyPath = $this->keyStore->getPublicKeyPath($this->multiPairingEnabled ? (string)$kid : null);
		if ($publicKeyPath === null) {
			$this->respondJson(401, ['status' => 'unpaired', 'error' => 'Agent is not paired.']);
			return;
		}
		if (!$this->signatureService->verifySignature($publicKeyPath, $payload, $sigBinary)) {
			$this->respondJson(401, ['status' => 'invalid-signature', 'error' => 'Signature verification failed.']);
			return;
		}

		$nonceKey = $this->multiPairingEnabled ? (string)$kid : 'default';
		$nonceError = $this->nonceStore->checkAndStore($nonceKey, (string)$nonce, (string)$exp, $this->signatureService);
		if ($nonceError !== null) {
			$status = $nonceError === 'replay' ? 409 : 500;
			$message = $nonceError === 'replay'
				? 'Nonce already used.'
				: 'Unable to persist nonce.';
			$this->respondJson($status, ['status' => 'nonce-error', 'error' => $message]);
			return;
		}

		$instructionData = $this->instructionParser->parse((string)$instructions);
		if ($instructionData === null) {
			$this->respondJson(400, ['status' => 'invalid-instructions', 'error' => 'Unable to parse instructions payload.']);
			return;
		}

		$deviceContext = $this->instructionValidator->validate($instructionData);
		if (isset($deviceContext['error'])) {
			$this->respondJson(400, ['status' => $deviceContext['error'], 'error' => $deviceContext['message'] ?? 'Invalid request.']);
			return;
		}

		$tcpResult = $this->tcpClient->send(
			$deviceContext['ip'],
			$deviceContext['port'],
			$deviceContext['payloadBase64'],
			$deviceContext['payloadTimeoutMs'],
			$deviceContext['responseChecker']
		);
		if ($tcpResult['ok'] === false) {
			$this->respondJson(502, [
				'status' => 'tcp-error',
				'error' => $tcpResult['error'],
				'device' => ['ip' => $deviceContext['ip'], 'port' => (int)$deviceContext['port']],
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
			'model_class' => $this->responseCheckerFactory->resolveModelClass($deviceContext['responseChecker']),
			'device' => ['ip' => $deviceContext['ip'], 'port' => (int)$deviceContext['port']],
			'bytes_written' => $tcpResult['bytes_written'],
			'bytes_read' => $tcpResult['bytes_read'],
			'response' => $tcpResult['response'],
		]);
	}


	private function sendCors(): void
	{
		Cors::send($this->corsOrigin, $_SERVER['HTTP_ORIGIN'] ?? null);
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

	private function getEnvBool(array $fileEnv, string $key, bool $default): bool
	{
		$value = $this->getEnvValue($fileEnv, $key, null);
		if ($value === null) {
			return $default;
		}
		$normalized = strtolower(trim((string)$value));
		if ($normalized === '') {
			return $default;
		}
		if (in_array($normalized, ['1', 'true', 'yes', 'on'], true)) {
			return true;
		}
		if (in_array($normalized, ['0', 'false', 'no', 'off'], true)) {
			return false;
		}
		return $default;
	}

	private function handleRoot(): void
	{
		$paired = $this->keyStore->hasAnyKey();
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
