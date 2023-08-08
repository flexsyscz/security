<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator\Traits;

use Flexsyscz\Security\Authorizator\Attributes\AllowedRole;


trait RoleRequired
{
	public function checkPermissions($element): bool
	{
		$user = $this->getUser();
		if ($user->isLoggedIn()) {
			if (method_exists($element, 'getAttributes')) {
				$attributes = $element->getAttributes(AllowedRole::class);
				foreach ($attributes as $attribute) {
					foreach ($attribute->getArguments() as $argument) {
						if ($user->isInRole($argument->value)) {
							return true;
						}
					}
				}
			}
		}

		return false;
	}
}
