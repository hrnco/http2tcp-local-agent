<?php
declare(strict_types=1);

namespace App\Services;

final class KeyStore implements KeyStoreInterface
{
	private string $dataDir;
	private string $publicKeyPath;
	private Base64Service $base64;

	public function __construct(string $dataDir, string $publicKeyPath, Base64Service $base64)
	{
		$this->dataDir = $dataDir;
		$this->publicKeyPath = $publicKeyPath;
		$this->base64 = $base64;
	}

	public function ensurePaired(?string $kid, ?string $pub): array
	{
		if (!is_dir($this->dataDir)) {
			@mkdir($this->dataDir, 0775, true);
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

	public function fingerprint(): string
	{
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

	private function ed25519RawToPem(string $rawKey): string
	{
		$der = hex2bin('302a300506032b6570032100') . $rawKey;
		$b64 = chunk_split(base64_encode($der), 64, "\n");
		return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
	}
}
