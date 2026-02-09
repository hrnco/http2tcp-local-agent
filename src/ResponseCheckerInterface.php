<?php
declare(strict_types=1);

namespace App;

interface ResponseCheckerInterface
{
	public function pushResponse(string $bytes, string $requestBytes): void;
	public function isComplete(): bool;
}
