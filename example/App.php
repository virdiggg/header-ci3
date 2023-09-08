<?php defined('BASEPATH') or exit('No direct script access allowed');

use Virdiggg\HeaderCi3;

class App extends CI_Controller
{
	private $headers;
	public function __construct()
	{
		parent::__construct();
	}

	private function test_secure_header()
	{
		$this->headers = new Headers();
		echo 1;
		return;
	}

	private function test_header()
	{
		echo 1;
		return;
	}
}