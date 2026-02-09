<?php
declare(strict_types=1);

namespace App\Services;

final class Base64Service
{
	public function decode(string $data): ?string
	{
		$decoded = base64_decode($data, true);
		if ($decoded !== false) {
			return $decoded;
		}
		return $this->base64urlDecode($data);
	}

	public function base64urlDecode(string $value): ?string
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

	public function base64urlEncode(string $value): string
	{
		return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
	}
}
