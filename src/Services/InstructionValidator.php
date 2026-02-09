<?php
declare(strict_types=1);

namespace App\Services;

final class InstructionValidator
{
	private int $readTimeout;
	private Base64Service $base64;

	public function __construct(int $readTimeout, Base64Service $base64)
	{
		$this->readTimeout = $readTimeout;
		$this->base64 = $base64;
	}

	public function validate(array $instructionData): ?array
	{
		$deviceIp = $instructionData['deviceIp'] ?? null;
		$devicePort = $instructionData['devicePort'] ?? null;
		$payloadBase64 = $instructionData['payloadBase64'] ?? null;
		$payloadTimeoutMs = $instructionData['payloadTimeoutMs'] ?? $instructionData['payload_timeout_ms'] ?? null;
		$responseCheckerCode = $instructionData['responseChecker'] ?? $instructionData['response_checker'] ?? $instructionData['deviceModel'] ?? $instructionData['device_model'] ?? null;

		if (!$this->isValidDeviceHost($deviceIp)) {
			return ['error' => 'invalid-device-ip', 'message' => 'deviceIp is required and must be a valid IP or hostname.'];
		}
		$resolvedDeviceIp = $this->resolveDeviceIp((string)$deviceIp);
		if ($resolvedDeviceIp === null) {
			return ['error' => 'invalid-device-ip', 'message' => 'deviceIp is required and must resolve to a valid IP.'];
		}
		if (!is_numeric($devicePort) || (int)$devicePort < 1 || (int)$devicePort > 65535) {
			return ['error' => 'invalid-device-port', 'message' => 'devicePort must be 1-65535.'];
		}
		if ($payloadBase64 === null) {
			return ['error' => 'invalid-payload', 'message' => 'payloadBase64 is required.'];
		}
		if (is_string($payloadBase64)) {
			if ($payloadBase64 === '' || $this->base64->decode($payloadBase64) === null) {
				return ['error' => 'invalid-payload', 'message' => 'payloadBase64 must be base64 or base64url.'];
			}
		} elseif (is_array($payloadBase64)) {
			if ($payloadBase64 === []) {
				return ['error' => 'invalid-payload', 'message' => 'payloadBase64 array must not be empty.'];
			}
			foreach ($payloadBase64 as $chunk) {
				if (!is_string($chunk) || $chunk === '' || $this->base64->decode($chunk) === null) {
					return ['error' => 'invalid-payload', 'message' => 'payloadBase64 array items must be base64 or base64url strings.'];
				}
			}
		} else {
			return ['error' => 'invalid-payload', 'message' => 'payloadBase64 must be a base64 string or array of base64 strings.'];
		}

		return [
			'ip' => $resolvedDeviceIp,
			'port' => (int)$devicePort,
			'payloadBase64' => $payloadBase64,
			'payloadTimeoutMs' => $payloadTimeoutMs ?? ($this->readTimeout * 1000),
			'responseChecker' => $responseCheckerCode,
		];
	}

	private function isValidDeviceHost(mixed $host): bool
	{
		if (!is_string($host)) {
			return false;
		}
		$host = trim($host);
		if ($host === '') {
			return false;
		}
		if (filter_var($host, FILTER_VALIDATE_IP)) {
			return true;
		}
		if (strcasecmp($host, 'localhost') === 0) {
			return true;
		}
		if (filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
			return true;
		}
		return (bool) preg_match('/^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)$/', $host);
	}

	private function resolveDeviceIp(string $host): ?string
	{
		if (filter_var($host, FILTER_VALIDATE_IP)) {
			return $host;
		}

		$records = function_exists('dns_get_record')
			? @dns_get_record($host, DNS_A + DNS_AAAA)
			: [];
		if (is_array($records) && $records !== []) {
			foreach ($records as $record) {
				if (isset($record['ip']) && filter_var($record['ip'], FILTER_VALIDATE_IP)) {
					return $record['ip'];
				}
			}
			foreach ($records as $record) {
				if (isset($record['ipv6']) && filter_var($record['ipv6'], FILTER_VALIDATE_IP)) {
					return $record['ipv6'];
				}
			}
		}

		$ipv4 = gethostbyname($host);
		if ($ipv4 !== $host && filter_var($ipv4, FILTER_VALIDATE_IP)) {
			return $ipv4;
		}

		return null;
	}
}
