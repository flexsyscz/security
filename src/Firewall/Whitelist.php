<?php

namespace Flexsyscz\Security\Firewall;

use Nette\IOException;
use Nette\SmartObject;
use Nette\Utils\FileSystem;


/**
 * @property-read string[]  $remoteAddresses
 */
final class Whitelist extends Jail
{
	use SmartObject;

	private const TempFileName = 'whitelist.dat';

	/** @var string[] */
	private array $ranges = [];

	/** @var string[] */
	private array $remoteAddresses = [];


	public function loadTempFile(): self
	{
		$tempFile = $this->getTempFile(self::TempFileName);
		if(file_exists($tempFile)) {
			try {
				$remoteAddresses = @unserialize(FileSystem::read($tempFile));
				if (is_array($remoteAddresses)) {
					$this->remoteAddresses = $remoteAddresses;
				}
			} catch (IOException $e) {
				// @todo logger
			}
		}

		return $this;
	}


	/**
	 * @param string[] $ranges
	 * @return void
	 */
	public function setRanges(array $ranges): void
	{
		$this->ranges = $ranges;
	}


	/**
	 * @param string[] $remoteAddresses
	 * @return void
	 */
	public function setRemoteAddresses(array $remoteAddresses): void
	{
		foreach ($remoteAddresses as $remoteAddress) {
			$this->remoteAddresses[$remoteAddress] = $remoteAddress;
		}
	}


	public function matchRemoteAddress(string $remoteAddress): bool
	{
		foreach ($this->remoteAddresses as $whitelistAddress) {
			if ($this->match($remoteAddress, $whitelistAddress)) {
				return true;
			}
		}

		foreach ($this->ranges as $range) {
			if ($this->match($remoteAddress, $range)) {
				return true;
			}
		}

		return false;
	}


	public function add(string $remoteAddress): self
	{
		$this->remoteAddresses[$remoteAddress] = $remoteAddress;

		return $this;
	}


	public function remove(string $remoteAddress): self
	{
		unset($this->remoteAddresses[$remoteAddress]);

		return $this;
	}


	public function __destruct()
	{
		$tempFile = $this->getTempFile(self::TempFileName);
		try {
			FileSystem::write($tempFile, serialize($this->remoteAddresses));
		} catch (IOException $e) {
			// @todo logger
		}
	}
}
