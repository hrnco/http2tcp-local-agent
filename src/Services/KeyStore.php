<?php
declare(strict_types=1);

namespace App\Services;

final class KeyStore implements KeyStoreInterface
{
	private string $dataDir;
	private string $publicKeyPath;
	private Base64Service $base64;
	private Ed25519KeyParser $keyParser;
	private string $keysDir;

	public function __construct(string $dataDir, string $publicKeyPath, Base64Service $base64, Ed25519KeyParser $keyParser)
	{
		$this->dataDir = $dataDir;
		$this->publicKeyPath = $publicKeyPath;
		$this->keysDir = $this->dataDir . '/keys';
		$this->base64 = $base64;
		$this->keyParser = $keyParser;
	}

	public function ensurePaired(?string $kid, ?string $pub): array
	{
		if (!$this->ensureDir($this->dataDir)) {
			return [
				'ok' => false,
				'status' => 500,
				'code' => 'storage-error',
				'error' => 'Unable to create data directory.',
			];
		}

		$resolvedKid = $this->normalizeKid($kid, $pub);
		if ($resolvedKid !== null) {
			if (!$this->ensureDir($this->keysDir)) {
				return [
					'ok' => false,
					'status' => 500,
					'code' => 'storage-error',
					'error' => 'Unable to create keys directory.',
				];
			}
			$perKeyPath = $this->getKeyPathForKid($resolvedKid);
			if (!is_file($perKeyPath)) {
				$pem = $this->resolvePublicKeyPem($kid, $pub);
				if ($pem === null) {
					return [
						'ok' => false,
						'status' => 401,
						'code' => 'unpaired',
						'error' => 'Agent is not paired. Provide public key as `kid` (base64url raw key) or `pub` (PEM).',
					];
				}
				file_put_contents($perKeyPath, $pem, LOCK_EX);
				if (!is_file($this->publicKeyPath) && !copy($perKeyPath, $this->publicKeyPath)) {
					error_log(sprintf('http2tcp-agent: failed to copy %s to %s', $perKeyPath, $this->publicKeyPath));
				}
				return ['ok' => true];
			}

			if ($pub !== null || $kid !== null) {
				$existing = trim((string)file_get_contents($perKeyPath));
				$provided = $this->resolvePublicKeyPem($kid, $pub);
				if ($provided !== null && trim($provided) !== $existing) {
					return [
						'ok' => false,
						'status' => 401,
						'code' => 'public-key-mismatch',
						'error' => 'Provided public key does not match paired key.',
					];
				}
			}

			return ['ok' => true];
		}

		if (!is_file($this->publicKeyPath)) {
			$pem = $this->resolvePublicKeyPem($kid, $pub);
			if ($pem === null) {
				return [
					'ok' => false,
					'status' => 401,
					'code' => 'unpaired',
					'error' => 'Agent is not paired. Provide public key as `kid` (base64url raw key) or `pub` (PEM).',
				];
			}
			file_put_contents($this->publicKeyPath, $pem, LOCK_EX);
			return ['ok' => true];
		}

		if ($pub !== null || $kid !== null) {
			$existing = trim((string)file_get_contents($this->publicKeyPath));
			$provided = $this->resolvePublicKeyPem($kid, $pub);
			if ($provided !== null && trim($provided) !== $existing) {
				return [
					'ok' => false,
					'status' => 401,
					'code' => 'public-key-mismatch',
					'error' => 'Provided public key does not match paired key.',
				];
			}
		}

		return ['ok' => true];
	}

	public function getPublicKeyPath(?string $kid): ?string
	{
		$resolvedKid = $this->normalizeKid($kid, null);
		if ($resolvedKid !== null) {
			$perKeyPath = $this->getKeyPathForKid($resolvedKid);
			if (is_file($perKeyPath)) {
				return $perKeyPath;
			}
		}

		if (is_file($this->publicKeyPath)) {
			return $this->publicKeyPath;
		}

		return null;
	}

	public function hasAnyKey(): bool
	{
		if (is_file($this->publicKeyPath)) {
			return true;
		}
		if (!is_dir($this->keysDir)) {
			return false;
		}
		$files = glob($this->keysDir . '/public_*.pem');
		return is_array($files) && count($files) > 0;
	}

	public function defaultFingerprint(): ?string
	{
		if (!is_file($this->publicKeyPath)) {
			return null;
		}
		$data = file_get_contents($this->publicKeyPath);
		return hash('sha256', $data ?: '');
	}

	private function normalizePem(string $input): ?string
	{
		$trimmed = trim($input);
		if (str_contains($trimmed, 'BEGIN PUBLIC KEY')) {
			return $trimmed . "\n";
		}

		$decoded = $this->base64->decode($trimmed);
		if ($decoded !== null && str_contains($decoded, 'BEGIN PUBLIC KEY')) {
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
			$raw = $this->base64->base64urlDecode($kid);
			if ($raw !== null) {
				$pem = $this->keyParser->rawToPem($raw);
				if ($pem !== null) {
					return $pem;
				}
			}
		}

		return null;
	}

	private function normalizeKid(?string $kid, ?string $pub): ?string
	{
		if ($kid !== null) {
			$raw = $this->base64->base64urlDecode($kid);
			if ($raw !== null && strlen($raw) === Ed25519KeyParser::RAW_KEY_BYTES) {
				return $kid;
			}
		}

		if ($pub !== null) {
			$pem = $this->normalizePem($pub);
			if ($pem !== null) {
				$raw = $this->keyParser->pemToRaw($pem);
				if ($raw !== null) {
					return $this->base64->base64urlEncode($raw);
				}
			}
		}

		return null;
	}

	private function getKeyPathForKid(string $kid): string
	{
		return $this->keysDir . '/public_' . $this->sanitizeKid($kid) . '.pem';
	}

	private function sanitizeKid(string $kid): string
	{
		return preg_replace('/[^A-Za-z0-9_-]/', '', $kid) ?: 'invalid';
	}

	private function ensureDir(string $path): bool
	{
		if (is_dir($path)) {
			return true;
		}
		if (mkdir($path, 0775, true)) {
			return true;
		}
		return is_dir($path);
	}
}
