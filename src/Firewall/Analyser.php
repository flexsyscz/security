<?php

namespace Flexsyscz\Security\Firewall;


final class Analyser
{
	private const CookieBlock = 'auto-block';

	private ?string $remoteAddress;

	/** @var string[] */
	private array $cookies;

	private Blacklist $blacklist;
	private Whitelist $whitelist;
	private Watcher $watcher;


	public function __construct(Blacklist $blacklist, Whitelist $whitelist, Watcher $watcher)
	{
		$this->remoteAddress = $_SERVER['REMOTE_ADDR'] ?? null;
		$this->cookies = $_COOKIE;

		$this->blacklist = $blacklist;
		$this->whitelist = $whitelist;
		$this->watcher = $watcher;
	}


	/**
	 * @return void
	 * @throws BlockedRequestException
	 */
	public function analyse(): void
	{
		if($this->remoteAddress) {
			$remoteAddress = (string) $this->remoteAddress;

			if (isset($this->cookies[self::CookieBlock])) {
				$this->block();
			} else {
				if ($this->whitelist->matchRemoteAddress($remoteAddress)) {
					$this->blacklist->remove($remoteAddress);
					return;

				} else if ($this->blacklist->matchRemoteAddress($remoteAddress)) {
					$this->block();
				}
			}

			if (!$this->watcher->check($remoteAddress)) {
				$this->watcher->remove($remoteAddress);
				$this->block();
			}
			$this->accept();
		}
	}


	/**
	 * @return void
	 * @throws BlockedRequestException
	 */
	private function block(): void
	{
		if($this->remoteAddress) {
			$this->blacklist->add($this->remoteAddress);
			setcookie(self::CookieBlock, $this->remoteAddress, strtotime('+30 minutes'));
		}

		throw new BlockedRequestException('Blocked request.');
	}


	private function accept(): void
	{
		if($this->remoteAddress) {
			$this->watcher->add($this->remoteAddress);
		}
	}
}
