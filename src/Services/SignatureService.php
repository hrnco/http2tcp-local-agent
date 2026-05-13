<?php
declare(strict_types=1);

namespace App\Services;

final class SignatureService
{
	private Base64Service $base64;
	private Ed25519KeyParser $keyParser;

	public function __construct(Base64Service $base64, Ed25519KeyParser $keyParser)
	{
		$this->base64 = $base64;
		$this->keyParser = $keyParser;
	}

	public function canonicalPayload(string $signature_uid, string $signature_timestamp, string $signature_metadata, string $instructions, string $kid, string $exp, string $nonce): string
	{
		return 'signature_uid=' . rawurlencode($signature_uid)
			. '&signature_timestamp=' . rawurlencode($signature_timestamp)
			. '&signature_metadata=' . rawurlencode($signature_metadata)
			. '&instructions=' . rawurlencode($instructions)
			. '&kid=' . rawurlencode($kid)
			. '&exp=' . rawurlencode($exp)
			. '&nonce=' . rawurlencode($nonce);
	}

	public function decodeSignature(string $sig): ?string
	{
		return $this->base64->decode($sig);
	}

	public function verifySignature(string $publicKeyPath, string $payload, string $signature): bool
	{
		if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
			return false;
		}
		if (!is_file($publicKeyPath) || !is_readable($publicKeyPath)) {
			return false;
		}
		$pem = file_get_contents($publicKeyPath);
		if ($pem === false || $pem === '') {
			return false;
		}
		$rawKey = $this->keyParser->pemToRaw($pem);
		if ($rawKey === null) {
			return false;
		}
		try {
			return sodium_crypto_sign_verify_detached($signature, $payload, $rawKey);
		} catch (\SodiumException) {
			return false;
		}
	}

	public function parseExpiryTimestamp(string $exp): ?int
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
}
