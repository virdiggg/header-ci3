# A Simple HTTP Header for CodeIgniter 3

<img src="https://img.shields.io/packagist/php-v/virdiggg/header-ci3" /> <img src="https://img.shields.io/badge/codeigniter--version-3-green" /> <img src="https://img.shields.io/github/license/virdiggg/header-ci3" />

## Is [helmetjs/helmet](https://github.com/helmetjs/helmet) for CodeIgniter 3/PHP.

### HOW TO USE
- Install this library with composer
```
composer require virdiggg/header-ci3
```
- Load this library on your `application/config/config.php` or you can create a controller if you don't want to load this on all of your website. Example is `application/controller/App.php`
```
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
		$this->headers = new Headers();
		echo 1;
		return;
	}

	public function test_no_header()
	{
		echo 1;
		return;
	}
}
```
- Then CURL your website in cmd
```
curl -I http://localhost/codeigniter/app/test_header/

HTTP/1.1 200 OK
Date: Fri, 08 Sep 2023 00:00:00 GMT
Server: Apache/2.4.54 (Win64) OpenSSL/1.1.1q PHP/8.1.10
Content-Type: text/html; charset=UTF-8
```
```
curl -I http://localhost/codeigniter/app/test_no_header/

HTTP/1.1 200 OK
Date: Fri, 08 Sep 2023 00:00:00 GMT
Server: Apache/2.4.54 (Win64) OpenSSL/1.1.1q PHP/8.1.10
X-Powered-By: PHP/8.1.10
Content-Type: text/html; charset=UTF-8
```
```
curl -I http://localhost/codeigniter/app/testing1/

HTTP/1.1 200 OK
Date: Fri, 08 Sep 2023 00:00:00 GMT
Server: Apache/2.4.54 (Win64) OpenSSL/1.1.1q PHP/8.1.10
Content-Security-Policy: default-src 'self' base-uri 'self' font-src 'self' https: data: form-action 'self' frame-ancestors 'self' img-src 'self' data: object-src 'none' script-src 'self' script-src-attr 'none' style-src 'self' https: 'unsafe-inline' upgrade-insecure-requests
'unsafe-inline' *.gstatic.com *.googleapis.com *.jquery.com *.jsdelivr.net
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
Permissions-Policy: fullscreen=(self), geolocation=(self), camera=(self)
Strict-Transport-Security: max-age=15552000; includeSubDomains
Content-Type: text/html; charset=UTF-8
```
```
curl -I http://localhost/codeigniter/app/testing2/

HTTP/1.1 200 OK
Date: Fri, 08 Sep 2023 00:00:00 GMT
Server: Apache/2.4.54 (Win64) OpenSSL/1.1.1q PHP/8.1.10
Content-Security-Policy: default-src 'self'
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: off
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
Permissions-Policy: fullscreen=(self), geolocation=(self), camera=(self)
Strict-Transport-Security: max-age=15552000; includeSubDomains
Content-Type: text/html; charset=UTF-8
```
```
curl -I http://localhost/codeigniter/app/testing3/

HTTP/1.1 200 OK
Date: Fri, 08 Sep 2023 00:00:00 GMT
Server: Apache/2.4.54 (Win64) OpenSSL/1.1.1q PHP/8.1.10
Content-Security-Policy: default-src 'self' base-uri 'self' font-src 'self' https: data: form-action 'self' frame-ancestors 'self' img-src 'self' data: object-src 'none' script-src 'self' script-src-attr 'none' style-src 'self' https: 'unsafe-inline' upgrade-insecure-requests
'unsafe-inline' *.gstatic.com *.googleapis.com *.jquery.com *.jsdelivr.net
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
Origin-Agent-Cluster: ?1
Referrer-Policy: no-referrer
X-Content-Type-Options: nosniff
X-DNS-Prefetch-Control: on
X-Download-Options: noopen
X-Frame-Options: SAMEORIGIN
X-Permitted-Cross-Domain-Policies: none
X-XSS-Protection: 0
Permissions-Policy: fullscreen=(self), geolocation=(self), camera=(self)
Strict-Transport-Security: max-age=15552000; includeSubDomains
Content-Type: text/html; charset=UTF-8
```

### EXPLANATIONS
- Header `X-Powered-By` will always be removed once you load this library.
- This will use all the default HTTP Headers
```
$this->headers = new Headers();
$this->headers->setHeaders();
```
- This will modify `Content-Security-Policy` header, a powerful allow-list of what can happen on your page which mitigates many attacks. Be careful when using this as this can break your page if you're using 3rd party library such as FontAwesome. Parameter is an array.
```
$this->headers = new Headers();
$this->headers->setContentSecurityPolicy([array]);
$this->headers->setHeaders();
```
- This will modify `Cross-Origin-Opener-Policy` header, it helps process-isolate your page. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setCrossOriginOpenerPolicy('string');
$this->headers->setHeaders();
```
- This will modify `Cross-Origin-Resource-Policy` header, it blocks others from loading your resources cross-origin. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setCrossOriginResourcePolicy('string');
$this->headers->setHeaders();
```
- This will modify `Cross-Origin-Embedder-Policy` header, it configures embedding cross-origin resources into the document. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setCrossOriginResourcePolicy('string');
$this->headers->setHeaders();
```
- This will modify `Origin-Agent-Cluster` header, it changes process isolation to be origin-based. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setOriginAgentCluster('string');
$this->headers->setHeaders();
```
- This will modify `Referrer-Policy` header, it controls the [Referer](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer) header. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setReferrerPolicy('string');
$this->headers->setHeaders();
```
- This will modify `Strict-Transport-Security` header, it tells browsers to prefer HTTPS. Parameter is a string.
- Make sure whether you have CONST ENVIRONMENT or not, if you are not, this will create it's own ENVIRONMENT.
- If ENVIRONMENT = 'production' (most likely not localhost), it will add this header. Otherwise, no.
```
$this->headers = new Headers();
$this->headers->setStrictTransportSecurity('string');
$this->headers->setHeaders();
```
- This will modify `X-Content-Type-Options` header, it help avoids [MIME sniffing](https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing). Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setXContentTypeOptions('string');
$this->headers->setHeaders();
```
- This will modify `X-DNS-Prefetch-Control` header, it controls DNS prefetching. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setXDNSPrefetchControl('string');
$this->headers->setHeaders();
```
- This will modify `X-Download-Options` header, it forces downloads to be saved (Internet Explorer only). Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setXDownloadOptions('string');
$this->headers->setHeaders();
```
- This will modify `X-Frame-Options` header, a legacy header that mitigates [clickjacking](https://en.wikipedia.org/wiki/Clickjacking) attacks. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setXFrameOptions('string');
$this->headers->setHeaders();
```
- This will modify `X-Permitted-Cross-Domain-Policies` header, it controls cross-domain behavior for Adobe products, like Acrobat. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setXPermittedCrossDomainPolicies('string');
$this->headers->setHeaders();
```
- This will modify `X-XSS-Protection` header, a legacy header that tries to mitigate XSS attacks, but makes things worse, so we disables it. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setXXSSProtection('string');
$this->headers->setHeaders();
```
- This will modify `Permissions-Policy` header, it provides mechanisms for web developers to explicitly declare what functionality can and cannot be used on a website. Parameter is a string.
```
$this->headers = new Headers();
$this->headers->setPermissionPolicy('string');
$this->headers->setHeaders();
```