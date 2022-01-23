<?php namespace App\Server;

// $ php init.php -h 192.168.1.237 -p 11666
// $ php init.php -h192.168.1.237 -p11666 -t1 -d127.0.0.1:7171

if(PHP_SAPI !== 'cli'){
	die("Script needs to be ran in cli environment.\n");
}

require "../controller/SocketController.php";

use App\Controller\SocketController;

$opts = getopt("h:p:t:d:", ["host:", "port:", "tunneling:", "dest:"]);

(count($opts) >= 2 && count($opts) <= 4)
|| die("[\33[91m!\33[0m] assign:\n"
	  ."remote ip \t[-h/--host|192.168.1.6]\n"
	  ."port \t\t[-p/--port|11666]\n"
	  ."OPTIONAL\t::::::::::::::::::::::::::\n"
	  ."tunneling \t[-t/--tunneling|1|0]\n"
	  ."dest   \t\t[-d/--dest|127.0.0.1:7171]\n"
   );
$host_addr = array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
$host_port = array_key_exists("port", $opts) ? intval(trim($opts['port'])) : intval(trim($opts['p']));

if(array_key_exists("tunneling", $opts) || array_key_exists("t", $opts))
{
	$tunneling = array_key_exists("tunneling", $opts)
			   ? intval(trim($opts['tunneling']))
			   : intval(trim($opts['t']));

	if($tunneling === 1 && (array_key_exists("dest", $opts) || array_key_exists("d", $opts)))
	{
		$tunneled_addr = array_key_exists("dest", $opts) 
						? trim($opts['dest'])
						: trim($opts['d']);
	}
	else {
		echo "You cant set tunneling without an destination\n";
		exit(1);
	}
}
else {
	$tunneling = 0;
	$tunneled_addr = "";
}

$result = SocketController::init($host_addr, $host_port, $tunneling, $tunneled_addr);
echo "Final server function result: {$result} - ".($result !== 0 ? 'with error.' : 'success!')."\n";
exit($result);
?>