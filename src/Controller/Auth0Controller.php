<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;

class Auth0Controller extends AbstractController
{/**
 * Link to this controller to start the "connect" process
 */
    #[Route(path: "/connect/auth0", name: "connect_auth0_start")]
    public function connectAction(ClientRegistry $clientRegistry)
    {
        // on Symfony 3.3 or lower, $clientRegistry = $this->get('knpu.oauth2.registry');

        // will redirect to Auth0!
        return $clientRegistry
            ->getClient('auth0') // key used in config/packages/knpu_oauth2_client.yaml
            ->redirect();
    }

    /**
     * After going to Facebook, you're redirected back here
     * because this is the "redirect_route" you configured
     * in config/packages/knpu_oauth2_client.yaml
    */
    #[Route(path: "/connect/auth0/check", name: "connect_auth0_check")]
    public function connectCheckAction(Request $request, ClientRegistry $clientRegistry)
    {

    }
}