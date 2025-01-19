<?php

declare(strict_types=1);

namespace Flexsyscz\Security\User;

use Flexsyscz\Application\DI\Injectable;
use Flexsyscz\Model\Users\User;
use Flexsyscz\Model\Users\UsersFacade;
use Nette;


final class LoggedUser extends Nette\Security\User implements Injectable
{
	private UsersFacade $usersFacade;


	public function injectUsersFacade(UsersFacade $usersFacade): void
	{
		$this->usersFacade = $usersFacade;
	}


	public function getEntity(): ?User
	{
		$user = $this->usersFacade->getRepository()->getById($this->getIdentity()?->getId());
		if ($user instanceof User) {
			return $user;
		}

		return null;
	}
}
