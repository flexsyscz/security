<?php

declare(strict_types=1);

namespace Flexsyscz\Security\Authorizator;

use Nette;


interface Resource extends Nette\Security\Resource
{
	public const View = 'view';
	public const Create = 'create';
	public const Update = 'update';
	public const Delete = 'delete';
}
