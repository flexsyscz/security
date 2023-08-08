<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator\Traits;

use Flexsyscz\Security\Authorizator\Attributes\Privilege;
use Flexsyscz\Security\Authorizator\Permission;
use Nette\InvalidStateException;


trait AccessControlList
{
	private Permission $acl;


	public function injectAuthorizator(Permission $acl): void
	{
		$this->acl = $acl;
	}


	public function checkPermissions(mixed $element): bool
	{
		try {
			$user = $this->getUser();
			if ($user->isLoggedIn()) {
				if (method_exists($element, 'getAttributes')) {
					$attributes = $element->getAttributes(Privilege::class);
					foreach ($attributes as $attribute) {
						foreach ($attribute->getArguments() as $argument) {
							foreach ($this->getUser()->getRoles() as $role) {
								if ($this->acl->isAllowed($role, $this->getResourceId(), $argument)) {
									return true;
								}
							}
						}
					}
				}

				foreach ($this->getUser()->getRoles() as $role) {
					if ($this->acl->isAllowed($role, $this->getResourceId())) {
						return true;
					}
				}
			}
		} catch (InvalidStateException $e) {
			$this->flashError($e->getMessage());
		}

		return false;
	}
}
