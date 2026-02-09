<?php
declare(strict_types=1);

namespace App\Services;

use App\ResponseCheckers\ResponseCheckerFactory;
use App\ResponseCheckerInterface;

final class TcpClient
{
	private int $connectTimeout;
	private int $readTimeout;
	private ResponseCheckerFactory $checkerFactory;
	private Base64Service $base64;

	public function __construct(int $connectTimeout, int $readTimeout, ResponseCheckerFactory $checkerFactory, Base64Service $base64)
	{
		$this->connectTimeout = $connectTimeout;
		$this->readTimeout = $readTimeout;
		$this->checkerFactory = $checkerFactory;
		$this->base64 = $base64;
	}

	public function send(string $ip, int $port, string|array $payloadBase64, mixed $payloadTimeoutMs = null, mixed $responseCheckerCode = null): array
	{
		$payloadBase64Chunks = is_array($payloadBase64) ? array_values($payloadBase64) : [$payloadBase64];
		$timeoutMsList = $this->normalizeTimeouts($payloadTimeoutMs, count($payloadBase64Chunks));
		$payloadChunks = [];
		foreach ($payloadBase64Chunks as $chunk) {
			$binary = $this->base64->decode($chunk);
			if ($binary === null) {
				return ['ok' => false, 'error' => 'Invalid payload encoding.'];
			}
			$payloadChunks[] = $binary;
		}

		$errno = 0;
		$errstr = '';
		$fp = @fsockopen($ip, $port, $errno, $errstr, (float) $this->connectTimeout);
		if ($fp === false) {
			return ['ok' => false, 'error' => $errstr !== '' ? $errstr : 'Connection failed.'];
		}

		stream_set_blocking($fp, false);
		stream_set_timeout($fp, (int) $this->readTimeout);

		$responses = [];
		$responseByIndex = [];
		$allResponseBinary = '';
		$time = microtime(true);
		$responseSeq = 0;
		$requestDoneAt = [];
		$lastRequestIndex = null;

		$drainReads = function (float $firstByteWaitSec, float $idleWindowSec, ?ResponseCheckerInterface $checker, string $requestBytes) use ($fp, &$responseByIndex, &$allResponseBinary, &$lastRequestIndex): bool {
			$firstByteDeadline = microtime(true) + max(0.001, $firstByteWaitSec);
			$lastDataAt = null;
			while (true) {
				$r = [$fp];
				$w = null;
				$e = null;

				$now = microtime(true);
				if ($lastDataAt === null) {
					$remaining = $firstByteDeadline - $now;
					if ($remaining <= 0) {
						break;
					}
				} else {
					$remaining = ($lastDataAt + max(0.001, $idleWindowSec)) - $now;
					if ($remaining <= 0) {
						break;
					}
				}

				$sec = (int) max(0, floor($remaining));
				$usec = (int) max(0, ($remaining - $sec) * 1_000_000);

				$n = @stream_select($r, $w, $e, $sec, $usec);
				if ($n === false || $n === 0) {
					continue;
				}

				$chunk = fread($fp, 8192);
				if ($chunk === '' || $chunk === false) {
					break;
				}

				if ($lastRequestIndex !== null) {
					$responseByIndex[$lastRequestIndex] = ($responseByIndex[$lastRequestIndex] ?? '') . $chunk;
				}
				$allResponseBinary .= $chunk;
				$lastDataAt = microtime(true);
				if ($checker !== null) {
					$checker->pushResponse($chunk, $requestBytes);
					if ($checker->isComplete()) {
						return true;
					}
				}
			}
			return false;
		};

		$bytesWritten = 0;
		$lastChunkComplete = false;

		foreach ($payloadChunks as $index => $chunk) {
			// Ensure the whole chunk is written (fwrite may write partially)
			$offset = 0;
			$len = strlen($chunk);

			while ($offset < $len) {
				$written = fwrite($fp, substr($chunk, $offset));
				if ($written === false || $written === 0) {
					fclose($fp);
					return ['ok' => false, 'error' => 'Failed to write payload.'];
				}

				$offset += $written;
				$bytesWritten += $written;
			}

			// Read any responses produced after this chunk
			$lastRequestIndex = $index;
			$timeoutMs = $timeoutMsList[$index] ?? 2000;
			$firstByteSec = max(0.001, $timeoutMs / 1000);
			$checker = $this->checkerFactory->create($responseCheckerCode);
			$lastChunkComplete = $drainReads($firstByteSec, 0.3, $checker, $chunk);
			$requestDoneAt[$index] = microtime(true) - $time;
		}

		if (!$lastChunkComplete) {
			$drainReads(0.3, 0.3, null, '');
		}

		fclose($fp);

		foreach ($payloadBase64Chunks as $index => $requestBase64) {
			$resp = $responseByIndex[$index] ?? '';
			$responses[] = [
				'seq' => $responseSeq++,
				'time' => $requestDoneAt[$index] ?? (microtime(true) - $time),
				'phase' => 'after-send',
				'request_index' => $index,
				'request_base64' => $requestBase64,
				'response_base64' => $resp !== '' ? base64_encode($resp) : null,
			];
		}

		$bytesRead = strlen($allResponseBinary);

		return [
			'ok' => true,
			'bytes_written' => $bytesWritten,
			'bytes_read' => $bytesRead,
			'response_base64' => base64_encode($allResponseBinary),
			'response' => $responses,
		];
	}

	private function normalizeTimeouts(mixed $payloadTimeoutMs, int $count): array
	{
		if ($payloadTimeoutMs === null) {
			return [];
		}

		if (is_numeric($payloadTimeoutMs)) {
			$val = (int) $payloadTimeoutMs;
			if ($val <= 0) {
				return [];
			}
			return array_fill(0, $count, $val);
		}

		if (is_array($payloadTimeoutMs)) {
			$out = [];
			foreach (array_values($payloadTimeoutMs) as $i => $v) {
				if (!is_numeric($v)) {
					continue;
				}
				$iv = (int) $v;
				if ($iv > 0) {
					$out[$i] = $iv;
				}
			}
			return $out;
		}

		return [];
	}

}
