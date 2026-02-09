<?php
declare(strict_types=1);

namespace App\ResponseCheckers;

use App\ResponseCheckerInterface;

final class ModelResponseChecker implements ResponseCheckerInterface
{
	private string $buffer = '';
	private string $lastRequest = '';
	private string $modelClass;

	public function __construct(string $modelClass)
	{
		$this->modelClass = $modelClass;
	}

	public function pushResponse(string $bytes, string $requestBytes): void
	{
		if ($requestBytes !== $this->lastRequest) {
			$this->buffer = '';
		}
		$this->buffer .= $bytes;
		$this->lastRequest = $requestBytes;
	}

	public function isComplete(): bool
	{
		if (!class_exists($this->modelClass)) {
			return false;
		}
		if (!method_exists($this->modelClass, 'isResponseComplete')) {
			return false;
		}
		return (bool) $this->modelClass::isResponseComplete($this->buffer, $this->lastRequest);
	}
}
