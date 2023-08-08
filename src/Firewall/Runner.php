<?php

namespace Flexsyscz\Security\Firewall;

use Nette\SmartObject;


/**
 * @property-read Blacklist     $blacklist
 * @property-read Whitelist     $whitelist
 * @property-read Watcher       $watcher
 */
final class Runner
{
	use SmartObject;

	private Blacklist $blacklist;
	private Whitelist $whitelist;
	private Watcher $watcher;
	private Analyser $analyser;

	private bool $active = false;


	public function __construct(string $tempDir)
	{
		$this->blacklist = (new Blacklist($tempDir))->loadTempFile();
		$this->whitelist = (new Whitelist($tempDir))->loadTempFile();
		$this->watcher = (new Watcher($tempDir))->loadTempFile();

		$this->analyser = new Analyser($this->blacklist, $this->whitelist, $this->watcher);
	}


	/**
	 * @return void
	 * @throws BlockedRequestException
	 */
	public function run(): void
	{
		if($this->active) {
			$this->analyser->analyse();
		}
	}


	public function enable(): self
	{
		$this->active = true;

		return $this;
	}


	public function disable(): self
	{
		$this->active = false;

		return $this;
	}


	public function status(): void
	{
		// @todo
	}


	public function getBlacklist(): Blacklist
	{
		return $this->blacklist;
	}


	public function getWhitelist(): Whitelist
	{
		return $this->whitelist;
	}


	public function getWatcher(): Watcher
	{
		return $this->watcher;
	}
}
