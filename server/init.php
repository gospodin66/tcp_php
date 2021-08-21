<?php namespace App\Server;

if(PHP_SAPI !== 'cli'){
	die("Script needs to be ran in cli environment.\n");
}

require "../controller/SocketController.php";

use App\Controller\SocketController;

$opts = getopt("h:p:", ["host:", "port:"]);

(count($opts) === 2) || die("[\33[91m!\33[0m] assign remote ip [-h/--host], port [-p/--port]\n");
$host_addr = array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
$host_port = array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);


$result = SocketController::init($host_addr, $host_port);

echo "Final server function result: {$result}\n";

function write_log(string $file, string $str) {
	return (file_put_contents($file, '['.date('Y-m-d H:i:s').']'.$str, FILE_APPEND));
}


?>