<?php
declare(strict_types=1);

namespace App\Models;

final class FiskalProModel implements ModelInterface
{
	public static function isResponseComplete(string $responseBytes, string $requestBytes): bool
	{
		$hex = bin2hex($responseBytes);
		if (strlen($hex) < 4) {
			return false;
		}
		if (substr($hex, 0, 2) !== '00') {
			return false;
		}
		$lenHex = substr($hex, 2, 2);
		$len = hexdec($lenHex);
		$totalBytes = 2 + $len + 1;
		return strlen($responseBytes) >= $totalBytes;
	}
}
