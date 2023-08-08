<?php

namespace Flexsyscz\Security\Firewall;

use Nette\IOException;
use Nette\SmartObject;
use Nette\Utils\FileSystem;


/**
 * @property int    $requestsPerSecond
 */
final class Watcher extends Jail
{
	use SmartObject;

	private const TempFileName = 'watcher.dat';

	/** @var int[][][] */
	private array $remoteAddresses = [];

	private int $requestsPerSecond = 5;


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


	public function check(string $remoteAddress): bool
	{
		$limit = $this->requestsPerSecond;
		$counter = $failed = 0;

		if (isset($this->remoteAddresses[$remoteAddress]) && count($this->remoteAddresses[$remoteAddress]) >= max($limit, 5)) {
			$this->remoteAddresses[$remoteAddress] = array_slice($this->remoteAddresses[$remoteAddress], -250);
			$input = $this->remoteAddresses[$remoteAddress];
			krsort($input);

			$last = null;
			foreach ($input as $hrtime) {
				if($counter > 100 || $failed >= max($limit, 5)) {
					break;
				}

				if($last) {
					$secs = $last[0] - $hrtime[0];
					$nano = $last[1] - $hrtime[1];

					if($secs > 0) {
						$nano = $secs * 1e9 - $nano;
					}

					if(abs($nano) <= 1e9 / $limit * 1.2) {
						$failed++;
					}
				}

				$last = $hrtime;
				$counter++;
			}
		}

		return $failed < max($limit, 5);
	}


	public function add(string $remoteAddress): self
	{
		if(!isset($this->remoteAddresses[$remoteAddress])) {
			$this->remoteAddresses[$remoteAddress] = [];
		}

		$this->remoteAddresses[$remoteAddress][] = hrtime();

		return $this;
	}


	public function remove(string $remoteAddress): self
	{
		unset($this->remoteAddresses[$remoteAddress]);

		return $this;
	}


	public function setRequestsPerSecond(int $requestsPerSecond): self
	{
		$this->requestsPerSecond = $requestsPerSecond;
		$this->remoteAddresses = [];

		return $this;
	}


	public function getRequestsPerSecond(): int
	{
		return $this->requestsPerSecond;
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
