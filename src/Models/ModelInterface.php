<?php
declare(strict_types=1);

namespace App\Models;

interface ModelInterface
{
	public static function isResponseComplete(string $responseBytes, string $requestBytes): bool;
}
