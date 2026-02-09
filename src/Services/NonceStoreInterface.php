<?php
declare(strict_types=1);

namespace App\Services;

interface NonceStoreInterface
{
	public function checkAndStore(string $kid, string $nonce, string $exp, SignatureService $signatureService): ?string;
}
