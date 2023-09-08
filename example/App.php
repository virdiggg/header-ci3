<?php defined('BASEPATH') or exit('No direct script access allowed');

use Virdiggg\HeaderCi3\Headers;

class App extends CI_Controller
{
	private $headers;
	public function __construct()
	{
		parent::__construct();
	}

	public function testing1()
	{
		$this->headers = new Headers();
        $this->headers->setHeaders();
		return;
	}

	public function testing2()
	{
		$this->headers = new Headers();
        $this->headers->setContentSecurityPolicy(["default-src 'self'"]);
		$this->headers->setHeaders();
		echo 1;
		return;
	}

	public function testing3()
	{
		$this->headers = new Headers();
		$this->headers->setXDNSPrefetchControl('on');
		$this->headers->setHeaders();
		echo 1;
		return;
	}

	public function test_header()
	{
		echo 1;
		return;
	}
}