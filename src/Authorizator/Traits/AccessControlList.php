<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator\Traits;

use Flexsyscz\Security\Authorizator\Attributes\RequiredPermission;
use Flexsyscz\Security\Authorizator\Permission;
use Nette\InvalidStateException;


trait AccessControlList
{
	private Permission $acl;
	private bool $authorized = false;


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
					$attributes = $element->getAttributes(RequiredPermission::class);
					foreach ($attributes as $attribute) {
						foreach ($attribute->getArguments() as $argument) {
							foreach ($this->getUser()->getRoles() as $role) {
								if ($this->acl->isAllowed($role, $this->getResourceId(), $argument)) {
									return $this->authorized = true;
								}
							}
						}
					}
				}

				foreach ($this->getUser()->getRoles() as $role) {
					if ($this->acl->isAllowed($role, $this->getResourceId())) {
						return $this->authorized = true;
					}
				}
			}
		} catch (InvalidStateException $e) {
			$this->flashError($e->getMessage());
		}

		return $this->authorized;
	}


	public function isAuthorized(): bool
	{
		return $this->authorized;
	}


	public function setAuthorized(bool $authorized): self
	{
		$this->authorized = $authorized;
		return $this;
	}
}
