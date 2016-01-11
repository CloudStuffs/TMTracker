<?php
/**
 * Containes various detection methods
 *
 * @author Hemant Mann
 */
namespace Shared;

use WebBot\lib\WebBot\Bot as Bot;

class Detector {
	
	/**
	 * @param array $opts Array of options containing array of urls to be executed
	 * whether or not response in json is required
	 */
	protected static function _execute($opts) {
		$bot = new Bot($opts['urls']);
		$bot->execute();
		$documents = $bot->getDocuments();

		$count = count($opts['urls']);
		if ($count == 1) {
			$doc = array_shift($documents);
			$body = $doc->getHttpResponse()->getBody();

			return ($opts['json']) ? json_decode($body) : $body;
		} elseif ($count > 1) {
			$return = array();
			foreach ($documents as $doc) {
				$return[$doc->uri] = $doc->getHttpResponse->getBody();
			}
			return $return;
		}
	}

	public static function IPInfo($ip) {
		$url = 'http://www.geoplugin.net/json.gp?ip='.$ip;
        return self::_execute(array(
        	'urls' => array('ip-info' => $url),
        	'json' => true
        ));
	}

	public static function UA($ua) {
		$ua = urlencode($ua);
		$url = "http://www.useragentstring.com/?getJSON=all&uas=$ua";
		return self::_execute(array(
			'urls' => array('user-agent' => $url),
			'json' => true
		));
	}
}