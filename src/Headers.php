<?php 

namespace Virdiggg\HeaderCi3;

class Headers
{
    /**
     * A powerful allow-list of what can happen on your page which mitigates many attacks
     * 
     * @return array
     */
    const CONTENT_SECURITY_POLICY = [
        "default-src 'self'",
        "base-uri 'self'",
        "font-src 'self' https: data:",
        "form-action 'self'", 
        "frame-ancestors 'self'",
        "img-src 'self' data:",
        "object-src 'none'", 
        "script-src 'self'",
        "script-src-attr 'none'",
        "style-src 'self' https: 'unsafe-inline'",
        "upgrade-insecure-requests"
    ];

    private $ContentSecurityPolicy = [];

    /**
     * Helps process-isolate your page
     * 
     * @return string
     */
    const CROSS_ORIGIN_OPENER_POLICY = 'same-origin';

    private $CrossOriginOpenerPolicy;

    /**
     * Blocks others from loading your resources cross-origin
     * 
     * @return string
     */
    const CROSS_ORIGIN_RESOURCE_POLICY = 'same-origin';

    private $CrossOriginResourcePolicy;

    /**
     * Changes process isolation to be origin-based
     * 
     * @return string
     */
    const ORIGIN_AGENT_CLUSTER = '?1';

    private $OriginAgentCluster = '?1';

    /**
     * Controls the Referer header
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referer
     * 
     * @return string
     */
    const REFERRER_POLICY = 'no-referrer';

    private $ReferrerPolicy;

    /**
     * Tells browsers to prefer HTTPS
     * 
     * @return string
     */
    const STRICT_TRANSPORT_SECURITY = 'max-age=15552000; includeSubDomains';

    private $StrictTransportSecurity;

    /**
     * Avoids MIME sniffing
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types#mime_sniffing
     * 
     * @return string
     */
    const X_CONTENT_TYPE_OPTIONS = 'nosniff';

    private $XContentTypeOptions;

    /**
     * Controls DNS prefetching
     * 
     * @return string
     */
    const X_DNS_PREFETCH_CONTROL = 'off';

    private $XDNSPrefetchControl;

    /**
     * Forces downloads to be saved (Internet Explorer only)
     * 
     * @return string
     */
    const X_DOWNLOAD_OPTIONS = 'noopen';

    private $XDownloadOptions;

    /**
     * Legacy header that mitigates clickjacking attacks
     * https://en.wikipedia.org/wiki/Clickjacking
     * 
     * @return string
     */
    const X_FRAME_OPTIONS = 'SAMEORIGIN';

    private $XFrameOptions;

    /**
     * Controls cross-domain behavior for Adobe products, like Acrobat
     * 
     * @return string
     */
    const X_PERMITTED_CROSS_DOMAIN_POLICIES = 'none';

    private $XPermittedCrossDomainPolicies;

    /**
     * Legacy header that tries to mitigate XSS attacks, but makes things worse, so Helmet disables it
     * 
     * @return string
     */
    const X_XSS_PROTECTION = '0';

    private $XXSSProtection;

    public function __construct()
    {
        // Info about the web server. Removed because it could be used in simple attacks.
        header_remove("X-Powered-By");

        // Set initial value
        $this->setContentSecurityPolicy(Headers::CONTENT_SECURITY_POLICY);
        $this->setCrossOriginOpenerPolicy(Headers::CROSS_ORIGIN_OPENER_POLICY);
        $this->setCrossOriginResourcePolicy(Headers::CROSS_ORIGIN_RESOURCE_POLICY);
        $this->setOriginAgentCluster(Headers::ORIGIN_AGENT_CLUSTER);
        $this->setReferrerPolicy(Headers::REFERRER_POLICY);
        $this->setStrictTransportSecurity(Headers::STRICT_TRANSPORT_SECURITY);
        $this->setXContentTypeOptions(Headers::X_CONTENT_TYPE_OPTIONS);
        $this->setXDNSPrefetchControl(Headers::X_DNS_PREFETCH_CONTROL);
        $this->setXDownloadOptions(Headers::X_DOWNLOAD_OPTIONS);
        $this->setXFrameOptions(Headers::X_FRAME_OPTIONS);
        $this->setXPermittedCrossDomainPolicies(Headers::X_PERMITTED_CROSS_DOMAIN_POLICIES);
        $this->setXXSSProtection(Headers::X_XSS_PROTECTION);

        // $this->setHeaders();
    }

    /**
     * Set HTTP header
     * 
     * @return void
     */
    public function setHeaders() {
        $headers = array_merge(
            $this->ContentSecurityPolicy(),
            $this->CrossOriginOpenerPolicy(),
            $this->CrossOriginResourcePolicy(),
            $this->OriginAgentCluster(),
            $this->ReferrerPolicy(),
            $this->XContentTypeOptions(),
            $this->XDNSPrefetchControl(),
            $this->XDownloadOptions(),
            $this->XFrameOptions(),
            $this->XPermittedCrossDomainPolicies(),
            $this->XXSSProtection(),
            // Localhost is not https
            $this->is_https() ? $this->StrictTransportSecurity() : []
        );

        foreach ($headers as $key => $value) {
            header($value, true);
        }
    }

    /**
     * HTTP Header Content-Security-Policy
     * 
     * @param array $param
     * 
     * @return array
     */
    private function ContentSecurityPolicy($param = []) {
        return ['Content-Security-Policy: ' . join(';', array_unique(array_merge($this->ContentSecurityPolicy, $param)))];
    }

    /**
     * Set HTTP Header Content-Security-Policy
     * 
     * @param array $param
     * 
     * @return void
     */
    public function setContentSecurityPolicy($param = Headers::CONTENT_SECURITY_POLICY) {
        $this->ContentSecurityPolicy = $param;
    }

    /**
     * HTTP Header Cross-Origin-Opener-Policy
     * 
     * @param string $param
     * 
     * @return array
     */
    private function CrossOriginOpenerPolicy($param = '') {
        return ['Cross-Origin-Opener-Policy: ' . (empty($param) ? $this->CrossOriginOpenerPolicy : $param)];
    }

    /**
     * Set HTTP Header Cross-Origin-Opener-Policy
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setCrossOriginOpenerPolicy($param = Headers::CROSS_ORIGIN_OPENER_POLICY) {
        $this->CrossOriginOpenerPolicy = $param;
    }

    /**
     * HTTP Header Cross-Origin-Resource-Policy
     * 
     * @param string $param
     * 
     * @return array
     */
    private function CrossOriginResourcePolicy($param = '') {
        return ['Cross-Origin-Resource-Policy: ' . (empty($param) ? $this->CrossOriginResourcePolicy : $param)];
    }

    /**
     * Set HTTP Header Cross-Origin-Opener-Policy
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setCrossOriginResourcePolicy($param = Headers::CROSS_ORIGIN_RESOURCE_POLICY) {
        $this->CrossOriginResourcePolicy = $param;
    }

    /**
     * HTTP Header Origin-Agent-Cluster
     * 
     * @param string $param
     * 
     * @return array
     */
    private function OriginAgentCluster($param = '') {
        return ['Origin-Agent-Cluster: ' . (empty($param) ? $this->OriginAgentCluster : $param)];
    }

    /**
     * Set HTTP Header Origin-Agent-Cluster
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setOriginAgentCluster($param = Headers::ORIGIN_AGENT_CLUSTER) {
        $this->OriginAgentCluster = $param;
    }

    /**
     * HTTP Header Referrer-Policy
     * 
     * @param string $param
     * 
     * @return array
     */
    private function ReferrerPolicy($param = '') {
        return ['Referrer-Policy: ' . (empty($param) ? $this->ReferrerPolicy: $param)];
    }

    /**
     * Set HTTP Header Referrer-Policy
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setReferrerPolicy($param = Headers::REFERRER_POLICY) {
        $this->ReferrerPolicy = $param;
    }

    /**
     * HTTP Header Strict-Transport-Security
     * 
     * @param string $param
     * 
     * @return array
     */
    private function StrictTransportSecurity($param = '') {
        return ['Strict-Transport-Security: ' . (empty($param) ? $this->StrictTransportSecurity: $param)];
    }

    /**
     * Set HTTP Header Strict-Transport-Security
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setStrictTransportSecurity($param = Headers::STRICT_TRANSPORT_SECURITY) {
        $this->StrictTransportSecurity = $param;
    }

    /**
     * HTTP Header X-Content-Type-Options
     * 
     * @param string $param
     * 
     * @return array
     */
    private function XContentTypeOptions($param = '') {
        return ['X-Content-Type-Options: ' . (empty($param) ? $this->XContentTypeOptions: $param)];
    }

    /**
     * Set HTTP Header X-Content-Type-Options
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setXContentTypeOptions($param = Headers::X_CONTENT_TYPE_OPTIONS) {
        $this->XContentTypeOptions = $param;
    }

    /**
     * HTTP Header X-DNS-Prefetch-Control
     * 
     * @param string $param
     * 
     * @return array
     */
    private function XDNSPrefetchControl($param = '') {
        return ['X-DNS-Prefetch-Control: ' . (empty($param) ? $this->XDNSPrefetchControl: $param)];
    }

    /**
     * Set HTTP Header X-DNS-Prefetch-Control
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setXDNSPrefetchControl($param = Headers::X_DNS_PREFETCH_CONTROL) {
        $this->XDNSPrefetchControl = $param;
    }

    /**
     * HTTP Header X-Download-Options
     * 
     * @param string $param
     * 
     * @return array
     */
    private function XDownloadOptions($param = '') {
        return ['X-Download-Options: ' . (empty($param) ? $this->XDownloadOptions: $param)];
    }

    /**
     * Set HTTP Header X-Download-Options
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setXDownloadOptions($param = Headers::X_DOWNLOAD_OPTIONS) {
        $this->XDownloadOptions = $param;
    }

    /**
     * HTTP Header X-Frame-Options
     * 
     * @param string $param
     * 
     * @return array
     */
    private function XFrameOptions($param = '') {
        return ['X-Frame-Options: ' . (empty($param) ? $this->XFrameOptions: $param)];
    }

    /**
     * Set HTTP Header X-Frame-Options
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setXFrameOptions($param = Headers::X_FRAME_OPTIONS) {
        $this->XFrameOptions = $param;
    }

    /**
     * HTTP Header X-Permitted-Cross-Domain-Policies
     * 
     * @param string $param
     * 
     * @return array
     */
    private function XPermittedCrossDomainPolicies($param = '') {
        return ['X-Permitted-Cross-Domain-Policies: ' . (empty($param) ? $this->XPermittedCrossDomainPolicies: $param)];
    }

    /**
     * Set HTTP Header X-Permitted-Cross-Domain-Policies
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setXPermittedCrossDomainPolicies($param = '') {
        $this->XPermittedCrossDomainPolicies = $param;
    }

    /**
     * HTTP Header X-XSS-Protection
     * 
     * @param string $param
     * 
     * @return array
     */
    private function XXSSProtection($param = '') {
        return ['X-XSS-Protection: ' . (empty($param) ? $this->XXSSProtection: $param)];
    }

    /**
     * Set HTTP Header X-XSS-Protection
     * 
     * @param string $param
     * 
     * @return void
     */
    public function setXXSSProtection($param = Headers::X_XSS_PROTECTION) {
        $this->XXSSProtection = $param;
    }

	/**
	 * Is HTTPS?
	 *
	 * Determines if the application is accessed via an encrypted
	 * (HTTPS) connection.
	 *
	 * @return bool
	 */
	private function is_https() {
		if (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') {
			return TRUE;
		} elseif (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https') {
			return TRUE;
		} elseif (!empty($_SERVER['HTTP_FRONT_END_HTTPS']) && strtolower($_SERVER['HTTP_FRONT_END_HTTPS']) !== 'off') {
			return TRUE;
		}

		return FALSE;
	}
}