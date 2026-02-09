<?php
declare(strict_types=1);

namespace App\Models;

final class FiskalProModel implements ModelInterface
{
	public static function responseTimeoutMsForRequest(string $requestBytes): ?int
	{
		$hex = bin2hex($requestBytes);
		if ($hex === '010100074654434c4f534544') {
            // 90 seconds
			return 90000;
		}
		return null;
	}

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
