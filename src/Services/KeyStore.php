<?php
declare(strict_types=1);

namespace App\Services;

final class KeyStore implements KeyStoreInterface
{
	private string $dataDir;
	private string $publicKeyPath;
	private Base64Service $base64;
	private string $keysDir;

	public function __construct(string $dataDir, string $publicKeyPath, Base64Service $base64)
	{
		$this->dataDir = $dataDir;
		$this->publicKeyPath = $publicKeyPath;
		$this->keysDir = $this->dataDir . '/keys';
		$this->base64 = $base64;
	}

	public function ensurePaired(?string $kid, ?string $pub): array
	{
		if (!is_dir($this->dataDir)) {
			@mkdir($this->dataDir, 0775, true);
		}

		$resolvedKid = $this->normalizeKid($kid, $pub);
		if ($resolvedKid !== null) {
			if (!is_dir($this->keysDir)) {
				@mkdir($this->keysDir, 0775, true);
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
				if (!is_file($this->publicKeyPath)) {
					@copy($perKeyPath, $this->publicKeyPath);
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
			if ($raw !== null && strlen($raw) === 32) {
				return $this->ed25519RawToPem($raw);
			}
		}

		return null;
	}

	private function normalizeKid(?string $kid, ?string $pub): ?string
	{
		if ($kid !== null) {
			$raw = $this->base64->base64urlDecode($kid);
			if ($raw !== null && strlen($raw) === 32) {
				return $kid;
			}
		}

		if ($pub !== null) {
			$pem = $this->normalizePem($pub);
			if ($pem !== null) {
				$raw = $this->pemToEd25519Raw($pem);
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

	private function ed25519RawToPem(string $rawKey): string
	{
		$der = hex2bin('302a300506032b6570032100') . $rawKey;
		$b64 = chunk_split(base64_encode($der), 64, "\n");
		return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
	}

	private function pemToEd25519Raw(string $pem): ?string
	{
		$decoded = $this->extractDerFromPem($pem);
		if ($decoded === null || strlen($decoded) < 12 + 32) {
			return null;
		}
		$prefix = hex2bin('302a300506032b6570032100');
		if ($prefix === false) {
			return null;
		}
		if (substr($decoded, 0, strlen($prefix)) !== $prefix) {
			return null;
		}
		return substr($decoded, strlen($prefix), 32);
	}

	private function extractDerFromPem(string $pem): ?string
	{
		$trimmed = trim($pem);
		$trimmed = preg_replace('/-----BEGIN PUBLIC KEY-----/', '', $trimmed);
		$trimmed = preg_replace('/-----END PUBLIC KEY-----/', '', $trimmed);
		$trimmed = trim((string)$trimmed);
		if ($trimmed === '') {
			return null;
		}
		$der = base64_decode($trimmed, true);
		if ($der === false) {
			return null;
		}
		return $der;
	}
}
