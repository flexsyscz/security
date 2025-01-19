<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator;

use Nette;


/**
 * @template T
 */
class Permission extends Nette\Security\Permission
{
	/**
	 * @param string $appDir
	 * @param string $tempDir
	 * @return Permission<T>
	 */
	protected function loadResources(string $appDir, string $tempDir): self
	{
		$loader = new Nette\Loaders\RobotLoader();
		$loader->addDirectory($appDir)
			->setTempDirectory($tempDir)
			->setAutoRefresh();

		$loader->rebuild();

		foreach (array_keys($loader->getIndexedClasses()) as $className) {
			if (($interfaces = class_implements($className))) {
				if (in_array(Nette\Security\Resource::class, $interfaces, true)) {
					/** @var class-string $className */
					$class = new \ReflectionClass($className);
					if (!$class->isAbstract()) {
						$this->addResource($className);
					}
				}
			}
		}

		return $this;
	}
}
