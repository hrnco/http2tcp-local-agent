<?php
declare(strict_types=1);

namespace App\Services;

final class Ed25519KeyParser
{
	public const RAW_KEY_BYTES = 32;
	private const DER_PREFIX_HEX = '302a300506032b6570032100';

	public function rawToPem(string $rawKey): ?string
	{
		if (strlen($rawKey) !== self::RAW_KEY_BYTES) {
			return null;
		}
		$prefix = hex2bin(self::DER_PREFIX_HEX);
		if ($prefix === false) {
			return null;
		}
		$der = $prefix . $rawKey;
		$b64 = chunk_split(base64_encode($der), 64, "\n");
		return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
	}

	public function pemToRaw(string $pem): ?string
	{
		$der = $this->extractDer($pem);
		if ($der === null) {
			return null;
		}
		$prefix = hex2bin(self::DER_PREFIX_HEX);
		if ($prefix === false) {
			return null;
		}
		$prefixLen = strlen($prefix);
		if (strlen($der) < $prefixLen + self::RAW_KEY_BYTES) {
			return null;
		}
		if (substr($der, 0, $prefixLen) !== $prefix) {
			return null;
		}
		return substr($der, $prefixLen, self::RAW_KEY_BYTES);
	}

	private function extractDer(string $pem): ?string
	{
		$trimmed = trim($pem);
		$trimmed = preg_replace('/-----BEGIN PUBLIC KEY-----/', '', $trimmed);
		$trimmed = preg_replace('/-----END PUBLIC KEY-----/', '', $trimmed);
		$trimmed = trim((string)$trimmed);
		if ($trimmed === '') {
			return null;
		}
		$der = base64_decode($trimmed, true);
		return $der === false ? null : $der;
	}
}
