<?php
use Shared\Registry as Registry;
use ClusterPoint\DB as DB;
use Shared\RequestMethods as RequestMethods;

Class Detector Extends Tracker {
	/**
	 * @constructor
	 */
	public function __construct() {
		$mongo = Registry::get("MongoDB");
		if (!$mongo) {
			$m = new MongoClient();
			$mongo = $m->stats;
			Registry::set("MongoDB", $mongo);
		}

		$parser = Registry::get("UAParser");
		if (!$parser) {
			$parser = UAParser\Parser::create();
			Registry::set("UAParser", $parser);
		}

	}
	/**
	 * Stores various actions
	 */
	protected static $_actions = array();

	/**
	 * Stores various triggers
	 */
	protected static $_triggers = array();

	/**
	 * Set actions if empty and returns the actions
	 * @return array
	 */
	protected function _actions() {
		if (empty(self::$_actions)) {
			$actions = array(
				"1" => array(
					"title" => "Do Nothing"
				),
				"2" => array(
					"title" => "Wait"
				),
				"3" => array(
					"title" => "Redirect"
				),
				"4" => array(
					"title" => "POST Values"
				),
				"5" => array(
					"title" => "Overlay Iframe"
				),
				"6" => array(
					"title" => "Popup"
				),
				"7" => array(
					"title" => "Hide Content"
				),
				"8" => array(
					"title" => "Replace Content"
				),
				"9" => array(
					"title" => "Send Email"
				),
				"10" => array(
					"title" => "Run Javascript"
				),
				"11" => array(
					"title" => "Run PHP"
				)
			);
			self::$_actions = $actions;
		}
		return self::$_actions;
	}

	/**
	 * Set triggers if empty and returns the triggers
	 * @return array
	 */
	protected function _triggers() {
		if (empty(self::$_triggers)) {
			$triggers = array(
				"1" => array(
					"title" => "PageView",
					"detect" => function ($opts) {
						return true;
					}
				),
				"2" => array(
					"title" => "Location",
					"detect" => function ($opts) {
						return strtolower($opts['user']['location']) == strtolower($opts['stored']);
					}
				),
				"3" => array(
					"title" => "Landing Page",
					"detect" => function ($opts) {
						$stored = strtolower($opts['saved']);
						$current = strtolower($opts['server']['landingPage']);
						return $current == $stored;
					}
				),
				"4" => array(
					"title" => "Time of Visit",
					"detect" => function ($opts) {
						$range = explode("-", $opts['saved']);
						
						$start = $range[0];
						$current = date('G:i');
						$end = $range[1];

						$start_time = strtotime($start);
						$current_time = strtotime($current);
						$end_time = strtotime($end);

						return ($current_time > $start_time && $current_time < $end_time);
					}
				),
				"5" => array(
					"title" => "Bots",
					"detect" => function ($opts) {
						$bots = explode(",", $opts['saved']);
						$response = false;
						foreach ($bots as $b) {
							if ($opts['user']['ua'] == trim($b)) {
								$response = true;
								break;
							}
						}

						if (strtolower($opts['saved']) == 'crawler' && $opts['user']['ua_info']->device->family == "Spider") {
							$response = true;
						}
						return $response;
					}
				),
				"6" => array(
					"title" => "IP Range",
					"detect" => function ($opts) {
						if (strpos($opts['saved'], '/') == false) {
						    $range.= '/32';
						}
						// $range is in IP/CIDR format eg 127.0.0.1/24
						list($opts['saved'], $netmask) = explode('/', $opts['saved'], 2);
						$range_decimal = ip2long($opts['saved']);
						$ip_decimal = ip2long($opts['user']['ip']);
						$wildcard_decimal = pow(2, (32 - $netmask)) - 1;
						$netmask_decimal = ~ $wildcard_decimal;
						return (($ip_decimal & $netmask_decimal) == ($range_decimal & $netmask_decimal));
					}
				),
				"7" => array(
					"title" => "User-Agent",
					"verify" => function ($inputs) {},
					"detect" => function ($opts) {
						return ($opts['user']['ua'] == $opts['saved']);
					}
				),
				"8" => array(
					"title" => "Browser",
					"detect" => function ($opts) {
						$current = $opts['user']['ua_info']->ua->family;
						$saved = $opts['saved'];
						return stristr($current, $saved);
					}
				),
				"9" => array(
					"title" => "Operating System",
					"detect" => function ($opts) {
						$current = $opts['user']['ua_info']->os->family;
						$saved = $opts['saved'];
						return stristr($current, $saved);
					}
				),
				"10" => array(
					"title" => "Device Type",
					"detect" => function ($opts) {
						$saved = strtolower($opts['saved']);

						$check = strtolower($opts['user']['ua_info']->device->family);
						switch ($check) {
							case 'other':
								$result = 'desktop';
								break;
							
							case 'android':
								$result = 'mobile';
								break;

							default:
								if (stristr($check, "Smartphone")) {
									$result = 'mobile';
								} elseif (stristr($opts['user']['ua_info']->os->family, "Android")) {
									$result = "mobile";
								} else {
									$result = false;
								}
								break;
						}
						if (!$result) {
							if (stristr($opts['user']['ua_info']->ua->family, "Mobile")) {
								$result = 'mobile';
							} else {
								$result = 'desktop';
							}
						}

						return ($saved == $result);
					}
				),
				"11" => array(
					"title" => "Referrer",
					"detect" => function ($opts) {
						$response = stristr($opts['server']['referer'], $opts['saved']);
						return ($response !== FALSE) ? true : false;
					}
				),
				"12" => array(
					"title" => "Active Login",
					"detect" => function ($opts) {
						return false;
					}
				),
				"13" => array(
					"title" => "Repeat Visitor",
					"detect" => function ($opts) {
						$cookie = $opts["cookies"];
						
						return isset($cookie["__trafficMonitor"]) ? true : false;
					}
				)
			);
			self::$_triggers = $triggers;
		}
		return self::$_triggers;
	}

	public function execute() {
		if (RequestMethods::post('plugin_detector') == 'getTrigger') {
			$data = $this->_setOpts();
			$mongo_db = Registry::get("MongoDB");
			$w_collection = $mongo_db->selectCollection("website");
			$website = $w_collection->findOne(array("url" => $data['server']['name']));

			if (!isset($website)) {
				echo 'return 0;';
				return;
			}

			$t_collection = $mongo_db->selectCollection("triggers");
			$a_collection = $mongo_db->selectCollection("actions");
			$triggers = $t_collection->find(array('website_id' => (string) $website["website_id"]));

			$code = ''; $last = '';
			$arr_triggers = $this->_triggers();
			$arr_actions = $this->_actions();
			foreach ($triggers as $t) {
				$key = $t["title"];
				$title = $arr_triggers["$key"]['title'];

				if (isset($arr_triggers["$key"]["detect"])) {
					$data['saved'] = $t["meta"];
					if (!call_user_func_array($arr_triggers["$key"]["detect"], array($data))) {
						continue;
					}
					
					//$this->googleAnalytics($website, $t, $data['user']['location']);
					$this->clusterpoint(array(
						"trigger_id" => $t["trigger_id"],
						"hit" => 1,
						"user_id" => $t["user_id"]
					));

					$action = $a_collection->findOne(array("trigger_id" => $t["trigger_id"]));
					$key = $action["title"];
					if ($arr_actions["$key"]["title"] == "Redirect") {
						$last .= $action["code"];
					} else {
						$code .= $action["code"];
					}
				}
			}
			$code .= $last;
			echo $code;
		} else {
			header("Location: http://trafficmonitor.ca");
			exit();
		}
	}

	protected function _log($message) {
		$logfile = APP_PATH . "/logs/" . date("Y-m-d") . ".txt";
        $new = file_exists($logfile) ? false : true;
        if ($handle = fopen($logfile, 'a')) {
            $timestamp = strftime("%Y-%m-%d %H:%M:%S", time());
            $content = "[{$timestamp}]{$message}\n";
            fwrite($handle, $content);
            fclose($handle);
            if ($new) {
                chmod($logfile, 0755);
            }
        } else {
            echo "Could not open log file for writing";
        }
	}

	protected function _setOpts() {
		$data = array();
		$data['user']['ip'] = $this->get_client_ip($_POST);
		$data['user']['ua'] = RequestMethods::post("HTTP_USER_AGENT");
		
		$parser = Registry::get("UAParser");
		$user_agent = $parser->parse($data['user']['ua']);
		
		$data['user']['location'] = $this->country($data['user']['ip']);
		$data['user']['ua_info'] = $user_agent;
		
		$data['server']['name'] = RequestMethods::post("HTTP_HOST");
		$data['server']['landingPage'] = 'http://'. $data['server']['name']. RequestMethods::post("REQUEST_URI");
		$data['server']['referer'] = RequestMethods::post("HTTP_REFERER");

		$data["posted"] = RequestMethods::post("p");
		$data["cookies"] = RequestMethods::post("c");
		$data["session"] = RequestMethods::post("s");
		
		return $data;
	}

	public function googleAnalytics($website, $trigger, $country) {
		$data = array(
			"v" => 1,
			"tid" => "",
			"cid" => $trigger["user_id"],
			"t" => "pageview",
			"dp" => $trigger["trigger_id"],
			"uid" => $trigger["user_id"],
			"ua" => "TrafficMonitor",
			"cn" => $trigger["title"],
			"cs" => $trigger["user_id"],
			"cm" => "TrafficMonitor",
			"ck" => $website["title"],
			"ci" => $trigger["user_id"],
			"dl" => $website["title"],
			"dh" => $website["url"],
			"dp" => $trigger["title"],
			"dt" => $country
		);

	    $url = "https://www.google-analytics.com/collect?".http_build_query($data);
	    // Get cURL resource
	    $curl = curl_init();
	    curl_setopt_array($curl, array(
	        CURLOPT_RETURNTRANSFER => 1,
	        CURLOPT_URL => $url,
	        CURLOPT_USERAGENT => 'CloudStuff'
	    ));

	    $resp = curl_exec($curl);
	    curl_close($curl);
	}

	protected function clusterpoint($data = array()) {
		$db = new DB();
		$record = $db->read($data);
		if($record) {
			$item = $record[0];
			$db->update($item->_id, $item->hit + 1);
		} else {
			$db->create($data);
		}
	}
}
