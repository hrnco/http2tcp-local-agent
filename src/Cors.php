<?php
declare(strict_types=1);

namespace App;

final class Cors
{
	public static function send(string $corsOrigin, ?string $requestOrigin): void
	{
		foreach (explode('|', $corsOrigin) as $origin) {
			$origin = trim($origin);
			if ($requestOrigin === null) {
				header('Access-Control-Allow-Origin: ' . $origin);
				break;
			}
			if (strcasecmp($requestOrigin, $origin) === 0) {
				header('Access-Control-Allow-Origin: ' . $origin);
				break;
			}
		}
		header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
		header('Access-Control-Allow-Headers: Content-Type, X-Custom-Header');
		if ($corsOrigin !== '*') {
			header('Access-Control-Allow-Credentials: true');
		}
	}
}
