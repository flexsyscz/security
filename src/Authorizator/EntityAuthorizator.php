<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator;

use Flexsyscz\FileSystem\Directories\AppDirectory;
use Flexsyscz\FileSystem\Directories\TempDirectory;
use Flexsyscz\Security\User\LoggedUser;
use Nette;
use Nextras\Orm\Entity\Entity;
use Nextras\Orm\Entity\IEntity;


final class EntityAuthorizator
{
	private LoggedUser $loggedUser;

	/** @var string[] */
	private array $entities = [];


	public function __construct(AppDirectory $appDirectory, TempDirectory $tempDirectory, LoggedUser $loggedUser)
	{
		$this->loggedUser = $loggedUser;

		$appDir = $appDirectory->getAbsolutePath();
		$tempDir = $tempDirectory->getAbsolutePath();

		$loader = new Nette\Loaders\RobotLoader();
		$loader->addDirectory($appDir)
			->setTempDirectory($tempDir)
			->setAutoRefresh();

		$loader->rebuild();

		foreach ($loader->getIndexedClasses() as $className => $file) {
			if (($parents = class_parents($className))) {
				if (in_array(Entity::class, $parents, true) && method_exists($className, 'onAuthorize')) {
					$this->entities[] = $className;
				}
			}
		}
	}


	public function authorize(IEntity $entity): bool
	{
		$result = null;
		$className = get_class($entity);
		if (in_array($className, $this->entities, true)) {
			if (method_exists($entity, 'onAuthorize')) {
				$result = call_user_func([$entity, 'onAuthorize'], $this->loggedUser);
			}
			return is_bool($result) ? $result : false;
		}

		return true;
	}
}
