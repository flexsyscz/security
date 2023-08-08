<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator;

use Nette;


class Permission extends Nette\Security\Permission
{
	protected function loadResources(string $appDir, string $tempDir): self
	{
		$loader = new Nette\Loaders\RobotLoader();
		$loader->addDirectory($appDir)
			->setTempDirectory($tempDir)
			->setAutoRefresh();

		$loader->rebuild();

		foreach ($loader->getIndexedClasses() as $className => $file) {
			if (($interfaces = class_implements($className))) {
				if (in_array(Nette\Security\Resource::class, $interfaces, true)) {
					$this->addResource($className);
				}
			}
		}

		return $this;
	}
}
