<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator\Attributes;

use Attribute;


#[Attribute]
class RequiredPermission
{
	public function __construct(...$params)
	{
	}
}
