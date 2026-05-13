<?php
declare(strict_types=1);

namespace App\Services;

final class NonceStore implements NonceStoreInterface
{
	private string $path;
	private int $ttl;

	public function __construct(string $path, int $ttl)
	{
		$this->path = $path;
		$this->ttl = $ttl;
	}

	public function checkAndStore(string $kid, string $nonce, string $exp, SignatureService $signatureService): ?string
	{
		if ($this->ttl <= 0) {
			return null;
		}

		$now = time();
		$expInt = $signatureService->parseExpiryTimestamp($exp) ?? ($now + $this->ttl);
		$expiresAt = min($expInt, $now + $this->ttl);

		$dir = dirname($this->path);
		if (!is_dir($dir) && !mkdir($dir, 0775, true) && !is_dir($dir)) {
			return 'store-unavailable';
		}
		$fp = fopen($this->path, 'c+');
		if ($fp === false) {
			return 'store-unavailable';
		}

		if (!flock($fp, LOCK_EX)) {
			fclose($fp);
			return 'store-unavailable';
		}

		$contents = stream_get_contents($fp);
		$store = json_decode($contents ?: '', true);
		if (!is_array($store)) {
			$store = [];
		}

		foreach ($store as $key => $expiry) {
			if (!is_int($expiry)) {
				if (is_string($expiry) && ctype_digit($expiry)) {
					$expiry = (int)$expiry;
				} else {
					unset($store[$key]);
					continue;
				}
			}
			if ($expiry <= $now) {
				unset($store[$key]);
			}
		}

		$key = hash('sha256', $kid . '|' . $nonce);
		if (isset($store[$key]) && (int)$store[$key] > $now) {
			flock($fp, LOCK_UN);
			fclose($fp);
			return 'replay';
		}

		$store[$key] = $expiresAt;

		ftruncate($fp, 0);
		rewind($fp);
		fwrite($fp, json_encode($store, JSON_UNESCAPED_SLASHES));
		fflush($fp);
		flock($fp, LOCK_UN);
		fclose($fp);

		return null;
	}
}
