<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator\Traits;


trait AuthenticationRequired
{
	public function checkPermissions(mixed $element): bool
	{
		return $this->getUser()->isLoggedIn();
	}
}
