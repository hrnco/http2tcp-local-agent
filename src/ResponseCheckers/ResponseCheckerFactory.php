<?php
declare(strict_types=1);

namespace App\ResponseCheckers;

use App\ResponseCheckerInterface;

final class ResponseCheckerFactory
{
	public function create(mixed $code): ?ResponseCheckerInterface
	{
		$modelClass = $this->resolveModelClass($code);
		if ($modelClass === null) {
			return null;
		}
		return new ModelResponseChecker($modelClass);
	}

	public function resolveModelClass(mixed $code): ?string
	{
		if (!is_string($code) || trim($code) === '') {
			return null;
		}
		$raw = trim($code);
		$full = ltrim($raw, '\\');
		if (class_exists($full)) {
			return $full;
		}
		$studly = $this->toStudly($raw);
		if ($studly === '') {
			return null;
		}
		$modelClass = 'App\\Models\\' . $studly . 'Model';
		if (class_exists($modelClass)) {
			return $modelClass;
		}
		return null;
	}

	private function toStudly(string $value): string
	{
		$parts = preg_split('/[^a-zA-Z0-9]+/', $value);
		if (!is_array($parts)) {
			return '';
		}
		$out = '';
		foreach ($parts as $part) {
			$part = trim($part);
			if ($part === '') {
				continue;
			}
			$out .= ucfirst(strtolower($part));
		}
		return $out;
	}
}
