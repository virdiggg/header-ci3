<?php defined('BASEPATH') or exit('No direct script access allowed');

use Virdiggg\HeaderCi3\Headers;

class App extends CI_Controller
{
	private $headers;
	public function __construct()
	{
		parent::__construct();
	}

	public function test_secure_header()
	{
		$this->headers = new Headers();
		$this->headers->setHeaders();
		echo 1;
		return;
	}

	public function test_secure_header_again()
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