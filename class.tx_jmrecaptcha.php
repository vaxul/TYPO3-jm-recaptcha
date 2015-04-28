<?php
/***************************************************************
 *  Copyright notice
 *
 *  (c) 2009 Markus Blaschke, TEQneers GmbH & Co. KG (blaschke@teqneers.de)
 *  (c) 2007 Jens Mittag (jens.mittag@prime23.de)
 *  All rights reserved
 *
 *  This script is part of the TYPO3 project. The TYPO3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

/**
 * Plugin 'reCAPTCHA' for the 'jm_recaptcha' extension.
 *
 * @author	Markus Blaschke, TEQneers GmbH & Co. KG <blaschke@teqneers.de>
 * @author	Jens Mittag <jens.mittag@prime23.de>
 */

class tx_jmrecaptcha extends tslib_pibase {
	public $prefixId		= 'tx_jmrecaptcha'; // Same as class name
	public $scriptRelPath	= 'class.tx_jmrecaptcha.php'; // Path to this script relative to the extension dir.
	public $extKey			= 'jm_recaptcha'; // The extension key.

	public $extConf = NULL;

	public function main($content, $conf) { }

	/**
	 * Build reCAPTCHA Frontend HTML-Code
	 *
	 * @param 	string	$error	Error Code (optional)
	 * @return	string			reCAPTCHA HTML-Code
	 */
	public function getReCaptcha($error = NULL) {
		global $TSFE;
		$this->pi_loadLL();

		// save plugin configuration inside a local array
		$conf = $TSFE->tmpl->setup['plugin.']['tx_jmrecaptcha.'];

		// extract server url and public key
		if($conf['use_ssl'] || !empty($_SERVER["HTTPS"]) || $_SERVER['SERVER_PORT'] == 443) {
			$server = rtrim($conf['api_server_secure'], '/');
		} else {
			$server = rtrim($conf['api_server'], '/');
		}
		$key = $conf['public_key'];

		// were any errors given in the last query?
		$err_parameter = '';
		if ($error) {
			$err__parameter = '&amp;error=' . $error;
		}

		###############################
		# reCaptcha Options
		###############################

		// Default settings
		$recaptchaOptions = array(
			'lang' => self::jsQuote('en'),
		);

		// Theme
		if( !empty($conf['theme']) ) {
			$recaptchaOptions['theme'] = self::jsQuote( $conf['theme'] );
		}

		// TabIndex
		if( !empty($conf['tabindex']) ) {
			$recaptchaOptions['tabindex'] = self::jsQuote( $conf['tabindex'] );
		}

		// TabIndex
		if( !empty($conf['custom_theme_widget']) ) {
			$recaptchaOptions['custom_theme_widget'] = self::jsQuote( $conf['custom_theme_widget'] );
		}

		// Language detection
		if( !empty($conf['lang']) ) {
			// language from plugin configuration
			$recaptchaOptions['lang'] = self::jsQuote( $conf['lang'] );
		} elseif( !empty($TSFE->tmpl->setup['config.']['language']) ) {
			// automatic language detection (TYPO3 settings)
			$recaptchaOptions['lang'] = self::jsQuote( $TSFE->tmpl->setup['config.']['language'] );
		}

		// Custom translations
		$customTranslations = array();

		if( !empty($conf['custom_translations.']) ) {
			foreach($conf['custom_translations.'] as $translationKey => $translationValue) {
				$customTranslations[] = $translationKey.' : '.self::jsQuote( $translationValue );
			}
		}
		if( !empty($customTranslations) ) {
			$recaptchaOptions['custom_translations'] = ' { '.implode(',',$customTranslations).' } ';
		}


		// Build option string
		$recaptchaOptionsTmp = array();
		foreach($recaptchaOptions as $optionKey => $optionValue) {
			$recaptchaOptionsTmp[] = $optionKey.' : '.$optionValue;
		}
		$recaptchaOptions = implode(', ', $recaptchaOptionsTmp);


		###############################
		# reCaptcha HTML
		###############################
		$content = '<script type="text/javascript">var RecaptchaOptions = { '.$recaptchaOptions.' };</script>';
		$content .= '<script type="text/javascript" src="'.htmlspecialchars($server.'/challenge?k='.$key.$err__parameter).'"></script>';
		$content .= '<noscript><iframe class="recaptcha-noscript-frame" src="'.htmlspecialchars($server.'/noscript?k='.$key).'" height="300" width="500" frameborder="0"></iframe><br /><p>'.$this->pi_getLL('enter_code_here').'</p><textarea class="recaptcha-noscript-textarea" name="recaptcha_challenge_field" rows="3" cols="40"></textarea><input type="hidden" name="recaptcha_response_field" value="manual_challenge" /></noscript>';
		return $content;
	}

	/**
	 * Quote js-param-value
	 *
	 * @param 	string	$value	Value
	 * @return	string			Quoted value
	 */
	protected static function jsQuote($value) {
		return '\''.addslashes( (string)$value ).'\'';
	}

	/**
	 * Validate reCAPTCHA challenge/response
	 *
	 * @return	array		Array with verified- (boolean) and error-code (string)
	 */
	public function validateReCaptcha() {
		global $TSFE;
		// save plugin configuration inside a local array
		$conf = $GLOBALS['TSFE']->tmpl->setup['plugin.']['tx_jmrecaptcha.'];

		// read out challenge, answer and remote_addr
		$data = array(
			'remoteip'		=> $_SERVER['REMOTE_ADDR'],
			'challenge'		=> trim( (string)t3lib_div::_GP('recaptcha_challenge_field') ),
			'response'		=> trim( (string)t3lib_div::_GP('recaptcha_response_field') ),
			'privatekey'	=> $conf['private_key'],
		);

		// first discard useless input
		if( empty($data['challenge']) || empty($data['response']) ) {
			return false;
		}

		if( $this->getExtConf('oldFetchMethod', false) ) {
			$result = $this->query_verification_server_old($data);
		} else {
			$result = $this->query_verification_server($data);
		}

		if(!$result) {
			return false;
		}

		// depending on the result, return appropriate status object
		$ret = array();
		if( strtolower($result[0]) == 'true' ) {
			$ret['verified']	= true;
			$ret['error']		= NULL;
		} else {
			$ret['verified']	= false;
			$ret['error']		= $result[1];
		}

		return $ret;
	}

	/**
	 * Query reCAPTCHA server for captcha-verification
	 *
	 * @param	array		Data
	 * @return	array		Array with verified- (boolean) and error-code (string)
	 */
	protected function query_verification_server($data) {
		global $TSFE;

		// save plugin configuration inside a local array
		$conf   = $TSFE->tmpl->setup['plugin.']['tx_jmrecaptcha.'];

		// find first occurence of '//' inside server string
		$verifyServerInfo = @parse_url( $conf['verify_server'] );

		if( empty($verifyServerInfo) ) {
			return array(false, 'recaptcha-not-reachable');
		}

		$paramStr = t3lib_div::implodeArrayForUrl('', $data);
		$ret = t3lib_div::getURL($conf['verify_server'] . '?' . $paramStr);

		return t3lib_div::trimExplode("\n", $ret);
	}

	/**
	 * Query reCAPTCHA server for captcha-verification
	 *
	 * @param	array		Data
	 * @return	array		Array with verified- (boolean) and error-code (string)
	 */
	protected function query_verification_server_old($data) {
		global $TSFE;

		// save plugin configuration inside a local array
		$conf	= $TSFE->tmpl->setup['plugin.']['tx_jmrecaptcha.'];

		// find first occurence of '//' inside server string
		$verifyServerInfo = @parse_url( $conf['verify_server'] );

		if( empty($verifyServerInfo) ) {
			return array(false, 'recaptcha-not-reachable');
		}

		// wrap parameters
		$req = $this->qsencode($data);

		// compose HTTP request
		$http_request  = "POST ".$verifyServerInfo['path']." HTTP/1.0\r\n";
		$http_request .= "Host: ".$verifyServerInfo['host']."\r\n";
		$http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
		$http_request .= "Content-Length: " . strlen($req) . "\r\n";
		$http_request .= "User-Agent: TYPO3/PHP\r\n";
		$http_request .= "\r\n";
		$http_request .= $req;

		// open socket
		if( !$fs = @fsockopen($verifyServerInfo['host'], $verifyServerInfo['port'], $errno, $errstr, 10) ) {
			return array(false, 'recaptcha-not-reachable');
		}

		// write request
		fwrite($fs, $http_request);

		// get response
		$response = '';
		while ( !feof($fs) ) {
			$response .= fgets($fs, 1160); // One TCP-IP packet
		}
		fclose($fs);
		$response = explode("\r\n\r\n", $response, 2);

		// return it
		return explode("\n", $response[1]);
	}

	/**
	 * QueryServer encode values
	 *
	 * @param	array		Data
	 * @return	array		Encoded data
	 */
	protected static function qsencode ($data) {
		$ret = "";

		foreach( $data as $key => $value ) {
			$ret .= $key . '=' . urlencode( stripslashes($value) ) . '&';
		}

		$ret = rtrim($ret, '&');

		return $ret;
	}

	/**
	 * Get extension configuration (by name)
	 *
	 * @param	string	$name			Configuration settings name
	 * @param	mixed	$defaultValue	Default value (if configuration doesn't exists)
	 * @return	mixed
	 */
	protected function getExtConf($name, $defaultValue = NULL) {
		global $TYPO3_CONF_VARS;

		if($this->extConf === NULL) {
			// Load ext conf
			$this->extConf = unserialize($TYPO3_CONF_VARS['EXT']['extConf']['jm_recaptcha']);
			if(!is_array($this->extConf)) {
				$this->extConf = array();
			}
		}

		$ret = $defaultValue;
		if(!empty($this->extConf[$name])) {
			$ret = $this->extConf[$name];
		}

		return $ret;
	}

}

if (defined('TYPO3_MODE') && $TYPO3_CONF_VARS[TYPO3_MODE]['XCLASS']['ext/jm_recaptcha/class.tx_jmrecaptcha.php'])	{
	include_once($TYPO3_CONF_VARS[TYPO3_MODE]['XCLASS']['ext/jm_recaptcha/class.tx_jmrecaptcha.php']);
}

?>
