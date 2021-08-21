<?php namespace App\Controller;

require "../models/Master.php";
require "../models/IncClient.php";

use App\Models\Master;
use App\Models\IncClient;
use Socket;

ob_implicit_flush(1);
define("DELIMITER", "----------------------------------------");
define("LOGFILE",".log");
define("BUFFER_LEN", 4096);
define("STREAM_BUFFER_LEN", 1024);
define("SERVER_ID", 'Server 11777');

class SocketController {

    public static function init($host_addr, $host_port){

        $master = new Master($host_addr, $host_port);

        echo "Host [".$master->addr.":".$master->port."] listening for incomming connections..\n\n";

        $clients = [ $master->socket ];
        /** stream_select() args => always null => only $_read used for stdin **/
        $write = $recv = $_recv = $connected = [];
        $except = $_except = $_write = [];

        while (1) {
            /** create a copy, so $clients doesn't get modified by socket_select() **/
            $write = $recv = $clients;
            $now = date('Y-m-d H:i:s');

            // reset if all dc
            if(empty($write) && empty($recv) && empty($clients)){
                $write = $recv = $clients = [ $master->socket ];
            }

            if(($recv_socket = stream_select($recv, $write, $except, 1, 000)) === false){
                echo "socket_select() error\n";
            }

            if(in_array($master->socket, $recv))
            {
                if(($recv_socket = stream_socket_accept($master->socket)) === false){
                    if ( ! is_resource($recv_socket)) {
                        echo "Connection could not be established\n";
                        continue;
                    }
                }
    
                if($recv_socket === 0){
                    /*
                     * ***********************************************
                     * no news after one second; we can do other tasks.
                     * Here we continue to wait for another second 
                     * ***********************************************
                     */
                    echo ".";
                    continue;
                }

                $client = new IncClient($recv_socket);
                $clients[] = $client->socket;    
                // $connected => list of client objects
                array_push($connected, $client);

                // remove the listening socket from the clients-with-data array
                $recv_key = array_search($clients, $recv);
                unset($recv[$recv_key]);

                echo "[".$now."] [\33[91m!\33[0m] [".$client->host.":".$client->ip.":".$client->port."] connected.\n";
            }
            $temp_master = $master->socket;
            $only_master_in_list = function($recv_arr) use ($temp_master) {
                                return (count($recv_arr) === 1 && $recv_arr[key($recv_arr)] === $temp_master);
                           };

            // don't want to read from self
            if( ! empty($recv) && ! $only_master_in_list($recv)){
                self::handle_recv_event($clients, $recv, $write, $connected);
            }

            $line = self::handle_stdin($_recv, $_write, $_except);

            self::process_line($line, $clients, $write, $recv, $connected, $master);
        }
        echo "closing master socket..\n";
        fclose($master->socket);
        return 0;
    }


    /**
     * 
     * 
     */
    private static function handle_stdin($r, $w, $e) : string {

        $stdin = fopen('php://stdin', 'r');

        stream_set_blocking($stdin, 0);

        $r = [ $stdin ];

        if(($result = stream_select($r, $w, $e, 0.2, 500000)) !== false){
            if($result === 0)  { 
                fclose($stdin);
                return "";
            }
            $line = stream_get_line($stdin, STREAM_BUFFER_LEN, "\n");
        }
        else {
            echo "[\33[91m!\33[0m] error: stream_select() error.\n";
            fclose($stdin);
            $line = "";
        }

        fclose($stdin);
        return $line;
    }


    /**
     * 
     * 
     */
    private static function display_clients(array $clients) : void {
        echo "\33[94mconnected clients: ".count($clients)."\33[0m\n";

        $clients = array_values($clients); // re-index

        foreach ($clients as $k => $c) { 
            echo "[{$k}]: {$c->id}:{$c->host}:{$c->ip}:{$c->port}\n";
        }

        return;
    }


    /**
     * @return 0 => success
     * @return 1 => continue
     * @return 2 => break
     */
    private static function process_line(
        string $line,
        array &$clients,
        array &$write,
        array &$recv,
        array &$connected,
        $master
    ) : int
    {
        if(empty($line)){ return 1; } 
        else if($line === 'exit'){ return 2; }
        else if($line === 'clients'){
            self::display_clients($connected);
            return 1;
        }
        else if($line === 'sendto'){
            self::display_clients($connected);

            $targetcmd = readline("ip::cmd [ or x to exit ]: ");

            $target = explode('::', $targetcmd);

            if($target[0] === 'x'){
                return 1;
            }

             if( ! empty($connected))
            {
                foreach($connected as $key => $_client)
                {
                    if($_client->ip === $target[0])
                    {
                        $temp_write = $_client->socket;

                        if($temp_write !== $master->socket) { /** don't write to self */
                            $key = array_search($temp_write,
                                        array_map(function($c) use ($temp_write) {
                                            return ($c->socket === $temp_write) ? $c->socket : null;
                                        }, $connected));
                            
                            $b = fwrite($temp_write, $target[1], strlen($target[1]));
    
                            if( ! $b){
                                echo "write message to websocket error.\n";
                                $r['err'] = 1;
                                continue;
                            }
    
                            echo "sent \33[35m{$b}\33[0m bytes to ONLY {$connected[$key]->id}\n";
                        }
                    }
                }
            }
        }
        else if($line === 'dcclient'){

            self::display_clients($connected);

            $target = readline("ip [ or x to exit ]: ");

            if($target === 'x'){
                return 1;
            }

            if( ! empty($connected))
            {
                foreach($connected as $key => $_client)
                {
                    if($_client->ip === $target)
                    {
                        $target = $_client->socket;

                        $k = array_search($target,
                                array_map(function($w) use ($target) {
                                    return ($w === $target) ? $w : null;
                                }, $write));

                        stream_socket_shutdown($target, STREAM_SHUT_RDWR);

                        echo "client {$_client->id} on socket {$target} disconnected by cmd.\n";

                        unset($clients[$k]);
                        unset($recv[$k]);
                        unset($write[$k]);
                        unset($connected[$key]);
                        break;
                    }
                }
            }
        }
        else { /** default send flow */
            if( ! empty($connected) && ! empty($write))
            {
                foreach ($write as $k => $w)
                {
                    if($w !== $master->socket) { /** don't write to self */
                        $key = array_search($w,
                                    array_map(function($c) use ($w) {
                                        return ($c->socket === $w) ? $c->socket : null;
                                    }, $connected));
                        
                        $b = fwrite($w, $line, strlen($line));

						if( ! $b){
							echo "write message to websocket error.\n";
                            $r['err'] = 1;
                            continue;
						}

                        echo "sent \33[35m{$b}\33[0m bytes to {$connected[$key]->id}\n";
                    }
                }
            }
        }
        return 0;
    }


    /**
     * @return 0 => success
     * @return 1 => continue
     * @return 2 => break
     */
    private static function handle_recv_event(
        &$clients,
        &$recv,
        &$write,
        &$connected
    ) : void {
        foreach ($recv as $key => &$r_socket)
        {
            if ( ! is_resource($r_socket)) {
                echo "passed recv socket is invalid.\n";
                break;
            }

            if(stream_set_blocking($r_socket, 0) === false){
                echo "error setting stream to non-block.\n";
                break;
            }

            $k = array_search($r_socket,
                        array_map(function($c) use ($r_socket) {
                            return ($c->socket === $r_socket) ? $c->socket : null;
                        }, $connected));
        
            if($k === false){
                echo "client not found on the list.. skipping...\n";

                stream_socket_shutdown($r_socket, STREAM_SHUT_RDWR);

                unset($clients[$key]);
                unset($recv[$key]);
                unset($write[$key]);
                unset($connected[$k]);
                
                break;
            }
            
            $ipport = stream_socket_get_name($r_socket, true);
            $ip = substr($ipport, 0, strpos($ipport, ':'));
            $port = substr($ipport, strpos($ipport, ':') +1, strlen($ipport));
            $host = gethostbyaddr($ip);

            if($connected[$k]->ip !== $ip && $connected[$k]->port !== $port){
                echo "overriding ip:port on client {$connected[$k]->id}\n";
                $connected[$k]->ip = $ip;
                $connected[$k]->port = $port;
            }

            $now = date('Y-m-d H:i:s');
            $data = '';
            $all_bytes = 0;

            // false indicates error
            while(1)
            {
                $recv_string = fread($r_socket, BUFFER_LEN);
                $bytes = mb_strlen($recv_string);
                
                $all_bytes += $bytes;

                echo $bytes !== 0 ? "\33[94mrecieved\33[0m: ".$bytes." \33[94mbytes\33[0m\n" : '';

                if($recv_string === false){ 
                    echo "recv_string false...\n";
                    break;
                }
                else if($bytes === 0)
                {
                    $connected[$k]->ttl++;

                    if(stream_get_meta_data($r_socket)['eof']){

                        stream_socket_shutdown($r_socket, STREAM_SHUT_RDWR);
    
                        echo "[".$now."] [\33[91m!\33[0m]"
                            ."[{$connected[$k]->host}:{$connected[$k]->ip}:{$connected[$k]->port}] disconnected after {$connected[$k]->ttl} ttl.\n";
    
                        unset($clients[$k]);
                        unset($recv[$k]);
                        unset($write[$k]);
                        unset($connected[$k]);
                    }
                    break;
                }
                else if ($bytes > 0){
                    $data .= $recv_string;
                }
                else {
                    echo "General stream recv() error!\n";
                }
            }
            if( ! empty($data))
            {
                if($all_bytes > BUFFER_LEN){
                    echo "\33[94moverall bytes recieved: ".$all_bytes."\33[0m\n";
                }
                echo "[\33[32m".$ip."\33[0m:\33[35m".$port."\33[0m]\n".$data."\n".DELIMITER."\n";
            }
        }
        unset($r_socket);
        return;
    }


}

?>