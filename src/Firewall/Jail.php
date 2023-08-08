<?php
declare(strict_types=1);

namespace Flexsyscz\Security\Firewall;

use Flexsyscz\Environment\TempStorage;


abstract class Jail
{
	private string $tempDir;


	public function __construct(string $tempDir)
	{
		$this->tempDir = $tempDir;
	}


	abstract public function add(string $remoteAddress): self;


	abstract public function remove(string $remoteAddress): self;


	protected function match(string $remoteAddress, ?string $range = null): bool
	{
		$parts = explode('/', (string) $range);
		$subnet = $parts[0];
		$bits = isset($parts[1]) ? (int) $parts[1] : null;

		if ($bits === null || $bits > 32) {
			$bits = 32;
		}

		$remoteAddress = ip2long($remoteAddress);
		$subnet = ip2long($subnet);
		$mask = -1 << (32 - $bits);
		$subnet &= $mask; # nb: in case the supplied subnet wasn't correctly aligned
		return ($remoteAddress & $mask) == $subnet;
	}


	protected function getTempFile(string $fileName): string
	{
		return sprintf('%s/%s', TempStorage::getDirectory($this->tempDir, 'firewall'), $fileName);
	}
}
