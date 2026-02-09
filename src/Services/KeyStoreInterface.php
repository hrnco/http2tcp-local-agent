<?php
declare(strict_types=1);

namespace App\Services;

interface KeyStoreInterface
{
	public function ensurePaired(?string $kid, ?string $pub): array;
	public function fingerprint(): string;
}
