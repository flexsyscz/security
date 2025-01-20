<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator;


enum Privilege: string
{
	case View = 'view';
	case Create = 'create';
	case Update = 'update';
	case Delete = 'delete';
}
