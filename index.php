<?php
require 'config.php';
require 'vendor/autoload.php';
require 'autoloader.php';
require 'tracker.php';
require 'detector.php';

$detector = new Detector();
$detector->execute();
?>
