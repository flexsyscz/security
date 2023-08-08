<?php

declare(strict_types=1);

namespace Tests\Security\Firewall;

use Flexsyscz\Security\Firewall\BlockedRequestException;
use Flexsyscz\Security\Firewall\Runner;
use Tester\Assert;
use Tester\TestCase;
use Tracy\Logger;

require __DIR__ . '/../bootstrap.php';


/**
 * @testCase
 */
class FirewallTest extends TestCase
{
	private string $logDir;
	private string $tempDir;


	public function setUp(): void
	{
		$this->logDir = __DIR__ . '/../log/' . getmypid();
		if(!is_dir($this->logDir)) {
			@mkdir($this->logDir);
		}

		$this->tempDir = __DIR__ . '/../temp/' . getmypid();
	}

	public function testBlacklist(): void
	{
		$remoteAddress = '192.168.88.1';
		$_SERVER['REMOTE_ADDR'] = $remoteAddress;
		$firewall = (new Runner($this->tempDir))->enable();

		Assert::exception(function() use ($firewall) {
			for($i = 0; $i < 10; $i++) {
				$firewall->run();
			}
		}, BlockedRequestException::class);
	}


	public function testBlacklist2(): void
	{
		$remoteAddress = '192.168.88.2';
		$_SERVER['REMOTE_ADDR'] = $remoteAddress;
		$firewall = (new Runner($this->tempDir))->enable();

		for($i = 0; $i < 10; $i++) {
			$firewall->run();
			usleep(intval(5e5));
		}

		Assert::exception(function() use ($firewall) {
			for($i = 0; $i < 10; $i++) {
				$firewall->run();
				usleep(intval(1e5));
			}
		}, BlockedRequestException::class);
	}


	public function testBlacklist3(): void
	{
		$remoteAddress = '192.168.88.3';
		$_SERVER['REMOTE_ADDR'] = $remoteAddress;
		$firewall = (new Runner($this->tempDir))->enable();

		$firewall->run();
		$firewall->blacklist->add($remoteAddress);

		Assert::exception(function() use ($firewall) {
			$firewall->run();
		}, BlockedRequestException::class);
	}


	public function testWhitelist(): void
	{
		$remoteAddress = '192.168.88.4';
		$_SERVER['REMOTE_ADDR'] = $remoteAddress;
		$firewall = (new Runner($this->tempDir))->enable();

		$firewall->run();

		$firewall->whitelist->add($remoteAddress);
		Assert::true($firewall->whitelist->matchRemoteAddress($remoteAddress));
	}


	public function testWatcher(): void
	{
		$remoteAddress = '192.168.88.5';
		$_SERVER['REMOTE_ADDR'] = $remoteAddress;
		$firewall = (new Runner($this->tempDir))->enable();

		$firewall->watcher->setRequestsPerSecond(8);
		for($i = 0; $i < 10; $i++) {
			$firewall->run();
			usleep(intval(3e5));
		}

		Assert::exception(function() use ($firewall) {
			for($i = 0; $i < 15; $i++) {
				$firewall->run();
				usleep(intval(90e3));
			}
		}, BlockedRequestException::class);

		$firewall->blacklist->remove($remoteAddress);
		$firewall->run();
	}
}

(new FirewallTest())->run();
