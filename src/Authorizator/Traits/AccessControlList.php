<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator\Traits;

use Flexsyscz\Security\Authorizator\Attributes\RequiredPermission;
use Flexsyscz\Security\Authorizator\Permission;
use Nette\InvalidStateException;
use Nette\Utils\Strings;


trait AccessControlList
{
	private Permission $acl;
	private bool $authorized = false;

	/** @var string[] */
	private array $authorizedSignals = [];


	public function injectAuthorizator(Permission $acl): void
	{
		$this->acl = $acl;
	}


	public function checkPermissions(mixed $element): bool
	{
		try {
			$user = $this->getUser();
			if ($user->isLoggedIn()) {
				if ($this->getSignal() !== null) {
					$authorizedSignal = false;
					if ($this->getSignal()[0] !== '') {
						$handler = sprintf('createComponent%s', Strings::firstUpper($this->getSignal()[0]));
					} else {
						$handler = sprintf('handle%s', Strings::firstUpper($this->getSignal()[1]));
					}

					if (!isset($this->authorizedSignals[$handler])) {
						if (method_exists($this, $handler)) {
							$ref = new \ReflectionClass($this);
							$method = $ref->getMethod($handler);
							$attributes = $method->getAttributes(RequiredPermission::class);
							if (count($attributes) === 0) {
								$authorizedSignal = true;
							} else {
								foreach ($attributes as $attribute) {
									foreach ($attribute->getArguments() as $argument) {
										if ($this->getUser()->isAllowed($this->getResourceId(), $argument)) {
											$authorizedSignal = true;
										}
									}
								}
							}
						} else {
							$authorizedSignal = true;
						}

						$this->authorizedSignals[$handler] = $authorizedSignal;
					}

					if (!$this->authorizedSignals[$handler]) {
						return false;
					}
				}

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
