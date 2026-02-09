<?php
declare(strict_types=1);

namespace App\Services;

final class SignatureService
{
	private Base64Service $base64;

	public function __construct(Base64Service $base64)
	{
		$this->base64 = $base64;
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
