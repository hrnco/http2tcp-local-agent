<?php
declare(strict_types=1);

namespace App\Services;

final class InstructionParser
{
	private Base64Service $base64;

	public function __construct(Base64Service $base64)
	{
		$this->base64 = $base64;
	}

	public function parse(string $instructions): ?array
	{
		$trimmed = trim($instructions);
		if ($trimmed === '') {
			return null;
		}

		$decodedJson = json_decode($trimmed, true);
		if (is_array($decodedJson)) {
			return $decodedJson;
		}

		$decodedBase64 = $this->base64->decode($trimmed);
		if ($decodedBase64 !== null) {
			$decodedJson = json_decode($decodedBase64, true);
			if (is_array($decodedJson)) {
				return $decodedJson;
			}
		}

		$parsed = [];
		parse_str($trimmed, $parsed);
		return $parsed !== [] ? $parsed : null;
	}
}
