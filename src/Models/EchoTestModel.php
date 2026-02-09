<?php
declare(strict_types=1);

namespace App\Models;

final class EchoTestModel
{
	public static function isResponseComplete(string $responseBytes, string $requestBytes): bool
	{
		if ($requestBytes === '') {
			return false;
		}
		if (strlen($responseBytes) < strlen($requestBytes)) {
			return false;
		}
        return false; // todo: docasne
		return substr($responseBytes, 0, strlen($requestBytes)) === $requestBytes;
	}
}
