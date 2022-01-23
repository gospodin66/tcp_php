<?php namespace App\Controller;

require "../models/Master.php";
require "../models/IncClient.php";
require "../encrypt/OpenSsl.php";

use App\Models\Master;
use App\Models\IncClient;
use App\Encrypt\OpenSsl;
use Socket;

ob_implicit_flush(1);

define("DELIMITER", "----------------------------------------");
define("LOGFILE",".log");
define("BUFFER_LEN", 4096);
define("STREAM_BUFFER_LEN", 1024);
define("SERVER_ID", 'Server 11777');

class SocketController {

    private const LOG = '../log/log.txt';
    private static array $write = [];
    private static array $recv = [];
    private static array $except = [];
    private static array $_write = [];
    private static array $_recv = [];
    private static array $_except = [];
    private static array $clients = [];
    private static array $connections_list = [];

    public static function init(string $host_addr, int $host_port, int $tunneling, string $tunneled_addr) {

        $master = new Master($host_addr, $host_port);

        echo "\n[\33[91m!\33[0m] Host listening for incomming connections on {$master->addr}:{$master->port}..\n";
        if ($tunneling === 1) { echo "[\33[91m!\33[0m] Tunneling traffic to: {$tunneled_addr}\n"; }

        self::$clients = [ $master->socket ];

        try {
            $log_dir = substr(self::LOG, 0, strrpos(self::LOG, '/'));
    
            if( ! is_dir($log_dir)){
                mkdir($log_dir, 0755, true);
            }
            
            while (1) {
                /** create a copy, so $clients doesn't get modified by socket_select() **/
                self::$write = self::$recv = self::$clients;
                if(empty(self::$write) && empty(self::$recv) && empty(self::$clients)){
                    self::$write = self::$recv = self::$clients = [ $master->socket ];
                }
                /** SOCKET/STREAM SELECT
                 * --------------------------------------------
                 * tv_sec  - num of seconds		 - 0.2
                 * tv_usec - num of microseconds - 500000 = 0.5
                 * --------------------------------------------
                 */
                if(($nconn = stream_select(self::$recv, self::$write, self::$except, 1, 000)) === false){
                    echo "[\33[91m!\33[0m] socket_select() error\n";
                }
                if($nconn === 0){
                    echo ".";
                    continue;
                }
                if( ! empty(self::$recv))
                {
                    if(in_array($master->socket, self::$recv))
                    {
                        // encrypted => true
                        if(0 !== self::handle_accept_socket($master, self::$recv, true, self::$connections_list, self::$clients)){
                            continue;
                        }
                    }
                    $temp_master = $master->socket;
                    $only_master_in_list =  function($recv_arr) use ($temp_master) {
                                                return (count($recv_arr) === 1 && $recv_arr[key($recv_arr)] === $temp_master);
                                            };
                    // don't want to read from self
                    if( ! $only_master_in_list(self::$recv)){
                        self::handle_recv_event($tunneling, $tunneled_addr, self::$clients, self::$recv, self::$write, self::$connections_list);
                    }
                }
                $line = self::handle_stdin(self::$_recv, self::$_write, self::$_except);
                $line_result = self::process_line($line, self::$clients, self::$write, self::$recv, self::$connections_list, $master);
    
                if($line_result === 0 || $line_result === 1){
                    continue;
                }
                else { break; }
            }
        } catch (\Throwable $th) {
            self::write_log($th->getMessage());
            echo "Oops! Fatal Error: {$th->getMessage()}\n";
            return 1;
        }
        
        echo "closing master socket..\n";
        fclose($master->socket);
        debug_zval_dump($master,self::$connections_list,self::$clients);
        return 0;
    }

    /**
     * accepts socket & creates a client obj
     * 
     * 0 success
     * 1 err => continue loop when exited
     */
    private static function handle_accept_socket(
        &$master,
        $recv,
        bool $uses_encryption,
        array &$connected_clients,
        array &$clients,
    ) : int
    {
        if(($recv_socket = stream_socket_accept($master->socket)) === false){
            if ( ! is_resource($recv_socket)) {
                echo "[\33[91m!\33[0m] connection could not be established\n";
                return 1;
            }
        }

        $client = new IncClient($recv_socket, $uses_encryption);

        echo "[\33[91m!\33[0m] ".
             $client->host.":".$client->ip.":".$client->port." connected.\n";
        self::write_log($client->host.":".$client->ip.":".$client->port." connected.\n");
        /** 
         * sending:
         *   signature +
         *   encrypted_AES-256-CBC_key_with_private_RSA +
         *   stripped_public_key
         */
        if($client->uses_encryption){
            $openssl = new OpenSsl;

            if(($b64_enc_metadata = $openssl->generate_metadata($client)) === null){
                echo "[\33[91m!\33[0m] generate encryption metadata error.\n";
                return 1;
            }

            $b = fwrite($client->socket, $b64_enc_metadata, mb_strlen($b64_enc_metadata));

            if( ! $b){
                echo "[\33[91m!\33[0m] send encryption metadata to socket error.\n";
                return 1;
            }
            echo "[\33[91m!\33[0m] sent encryption metadata to target: {$client->id}:{$client->host}:{$client->ip}:{$client->port}\n";
        }
        $clients[] = $client->socket;
        array_push($connected_clients, $client);
        // remove the listening socket from the clients-with-data array
        $recv_key = array_search($clients, $recv);
        unset($recv[$recv_key]);
        unset($client);
        unset($openssl);
        return 0;
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
        array &$connected_clients,
        $master
    ) : int
    {
        $openssl = new Openssl;

        if(empty($line)){ return 1; } 
        else if($line === 'exit'){ return 2; }
        else if($line === 'clients'){
            self::display_clients($connected_clients);
            return 1;
        }
        else if($line === 'sendto'){

            echo "select target by number: \n";
            foreach ($connected_clients as $k => $c) { 
                echo "[{$k}]: {$c->id}:{$c->host}:{$c->ip}:{$c->port}\n";
            }

            $target_num_msg = readline("[ number::msg | 'x' to exit ]: ");
            
            if($target_num_msg === 'x'){
                return 0;
            }

            if(strpos($target_num_msg, "::") === false){
                echo "[\33[91m!\33[0m] missing number'::'msg separator\n";
                return 1;
            }

            $target_num_msgarr = explode('::', $target_num_msg);

            if(count($target_num_msgarr) !== 2){
                echo "[\33[91m!\33[0m] format number::msg invalid.\n";
                return 1;
            }

            $target_num = $target_num_msgarr[0];
            $msg = $target_num_msgarr[1];

            if( ! is_numeric($target_num) || ! array_key_exists($target_num, $connected_clients)){
                echo "[\33[91m!\33[0m] target doesn't exist.\n";
                return 1;
            }

            $target = "{$connected_clients[$target_num]->ip}:{$connected_clients[$target_num]->port}";

            if( ! empty($connected_clients))
            {
                foreach($connected_clients as $key => $_client)
                {
                    if("{$_client->ip}:{$_client->port}" === $target)
                    {
                        $temp_write = $_client->socket;

                        if($temp_write !== $master->socket) { /** don't write to self */

                            $key = array_search($temp_write,
                                        array_map(function($c) use ($temp_write) {
                                            return ($c->socket === $temp_write) ? $c->socket : null;
                                        }, $connected_clients));

                            if($_client->uses_encryption){
                                $out = $openssl->encrypt_CBC($msg);
                            }
                            else {
                                $out = $msg;
                            }
                            
                            $b = fwrite($temp_write, $out, mb_strlen($out));
    
                            if( ! $b){
                                echo "[\33[91m!\33[0m] write message to socket error.\n";
                                $r['err'] = 1;
                                continue;
                            }
    
                            echo "[\33[91m!\33[0m] sent \33[35m{$b}\33[0m bytes to ONLY {$connected_clients[$key]->id}::{$connected_clients[$key]->host}:{$connected_clients[$key]->ip}:{$connected_clients[$key]->port}\n";
                        }
                    }
                }
            }
        }
        else if($line === 'dcclient'){

            echo "select target by number: \n";
            foreach ($connected_clients as $k => $c) { 
                echo "[{$k}]: {$c->id}:{$c->host}:{$c->ip}:{$c->port}\n";
            }

            $target_num = readline("[ number | 'x' to exit ]: ");
            
            if($target_num === 'x'){
                return 0;
            }
            
            if( ! is_numeric($target_num) || ! array_key_exists($target_num, $connected_clients)){
                echo "[\33[91m!\33[0m] target doesn't exist.\n";
                return 1;
            }

            $target = "{$connected_clients[$target_num]->ip}:{$connected_clients[$target_num]->port}";

            if( ! empty($connected_clients))
            {
                foreach($connected_clients as $key => $_client)
                {
                    if("{$_client->ip}:{$_client->port}" === $target)
                    {
                        $target_socket = $_client->socket;

                        $k = array_search($target_socket,
                                array_map(function($w) use ($target_socket) {
                                    return ($w === $target_socket) ? $w : null;
                                }, $write));

                        stream_socket_shutdown($target_socket, STREAM_SHUT_RDWR);

                        echo "[\33[91m!\33[0m] client {$_client->id} on socket {$target_socket} disconnected by command.\n";

                        self::write_log("client {$_client->id} - socket {$target_socket} - disconnected by command.\n");

                        unset($clients[$k]);
                        unset($recv[$k]);
                        unset($write[$k]);
                        unset($connected_clients[$key]);

                        break;
                    }
                }
            }
        }
        else if($line === 'dcall'){
            if( ! empty($connected_clients))
            {
                foreach($connected_clients as $key => $_client)
                {
                    $target_csock = $_client->socket;
                    $k = array_search($target_csock,
                            array_map(function($c) use ($target_csock) {
                                return ($c === $target_csock) ? $c : null;
                            }, $clients));

                    stream_socket_shutdown($target_csock, STREAM_SHUT_RDWR);
                    unset($clients[$k]);
                    unset($recv[$k]);
                    unset($write[$k]);
                    unset($connected_clients[$key]);

                    echo "client {$_client->id} on socket {$target_csock} disconnected by command.\n";
                    self::write_log("client {$_client->id} on socket {$target_csock} disconnected by command.\n");
                }
            }
        }
        else { self::broadcast_line($master, $line, $connected_clients, $write); }
        return 0;
    }


    /**
     * @return 0 => success
     * @return 1 => continue
     * @return 2 => break
     */
    private static function handle_recv_event(
        int $tunneling,
        string $tunneled_addr,
        array &$clients,
        array &$recv,
        array &$write,
        array &$connected_clients
    ) : void
    {
        $openssl = new OpenSsl;

        foreach ($recv as $key => &$r_socket)
        {
            if ( ! is_resource($r_socket)) {
                echo "[\33[91m!\33[0m] provided recv socket is invalid.\n";
                break;
            }

            if(stream_set_blocking($r_socket, 0) === false){
                echo "[\33[91m!\33[0m] error setting stream to non-block.\n";
                break;
            }
                    
            $k = array_search($r_socket,
                    array_map(function($c) use ($r_socket) {
                        return ($c->socket === $r_socket) ? $c->socket : null;
                    }, $connected_clients));

            if($k === false){
                echo "client with resource {$r_socket} doesn't exist.\n";
                continue;
            }

            $ipport = stream_socket_get_name($r_socket, true);

            if(empty($ipport)){
                stream_socket_shutdown($r_socket, STREAM_SHUT_RDWR);
    
                echo "[\33[91m!\33[0m] "
                    ."{$connected_clients[$k]->host}:{$connected_clients[$k]->ip}:{$connected_clients[$k]->port} "
                    ."disconnected due to having invalid IP:PORT string format.\n";
                self::write_log(
                    "{$connected_clients[$k]->host}:{$connected_clients[$k]->ip}:{$connected_clients[$k]->port} "
                    ."disconnected due to having invalid IP:PORT string format.\n"
                );

                echo "shutting down sockets: \n".
                    "key: \t  [{$key}]\n".
                    "clients:  {{$clients[$key]}]\n".
                    "recv: \t  {{$recv[$key]}]\n".
                    "write: \t  {{$write[$key]}]\n".
                    "conn: \t {{$connected_clients[$k]->socket}]\n\n";

                unset($clients[$key]);
                unset($recv[$key]);
                unset($write[$key]);
                unset($connected_clients[$k]);
                continue;
            }

            $ip = substr($ipport, 0, strpos($ipport, ':'));
            $port = substr($ipport, strpos($ipport, ':') +1, strlen($ipport));
            $host = gethostbyaddr($ip);


            if($connected_clients[$k]->ip !== $ip && $connected_clients[$k]->port !== $port){
                echo "[\33[91m!\33[0m] overriding ip:port on client {$connected_clients[$k]->id}\n";
                $connected_clients[$k]->ip = $ip;
                $connected_clients[$k]->port = intval($port);
            }

            $data = '';
            $all_bytes = 0;

            // false indicates error
            while(1)
            {
                $recv_string = fread($r_socket, BUFFER_LEN);
                $bytes = mb_strlen($recv_string);

                // \/ HTTP\/(2\.0|(1\.[0-1]{1})))
                if(preg_match('/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\s\//', $recv_string, $matches)){
                    echo "\n[\33[91m!\33[0m] HTTP {$matches[0]} request -> dropping & removing client..\n";

                    stream_socket_shutdown($r_socket, STREAM_SHUT_RDWR);
    
                    echo "[\33[91m!\33[0m] "
                        ."{$connected_clients[$k]->host}:{$connected_clients[$k]->ip}:{$connected_clients[$k]->port} "
                        ."disconnected due to being HTTP request.\n";
                    self::write_log(
                        "{$connected_clients[$k]->host}:{$connected_clients[$k]->ip}:{$connected_clients[$k]->port} "
                        ."disconnected due to being HTTP request.\n"
                    );

                    echo "shutting down sockets: \n".
                        "key: \t [{$key}]\n".
                        "clients: {{$clients[$key]}]\n".
                        "recv: \t {{$recv[$key]}]\n".
                        "write: \t {{$write[$key]}]\n".
                        "conn: \t {{$connected_clients[$k]->socket}]\n\n";

                    unset($clients[$key]);
                    unset($recv[$key]);
                    unset($write[$key]);
                    unset($connected_clients[$k]);
                    break;
                }
                
                $all_bytes += $bytes;

                echo $bytes !== 0 ? "\33[94mrecieved\33[0m: ".$bytes." \33[94mbytes\33[0m\n" : '';

                if($recv_string === false){ 
                    echo "[\33[91m!\33[0m] recv_string false...\n";
                    break;
                }
                else if($bytes === 0)
                {
                    $connected_clients[$k]->ttl++;

                    if(stream_get_meta_data($r_socket)['eof']){

                        stream_socket_shutdown($r_socket, STREAM_SHUT_RDWR);
    
                        echo "\n[\33[91m!\33[0m]"
                            ."{$connected_clients[$k]->host}:{$connected_clients[$k]->ip}:{$connected_clients[$k]->port} "
                            ."disconnected after {$connected_clients[$k]->ttl} ttl.\n";
                        self::write_log(
                            "{$connected_clients[$k]->host}:{$connected_clients[$k]->ip}:{$connected_clients[$k]->port} "
                            ."disconnected after {$connected_clients[$k]->ttl} ttl.\n"
                        );

                        echo //"\nclient with socket {{$r_socket}} not found on the list..\n".
                            "shutting down sockets: \n".
                            "key: \t [{$key}]\n".
                            "clients: {{$clients[$key]}]\n".
                            "recv: \t {{$recv[$key]}]\n".
                            "write: \t {{$write[$key]}]\n".
                            "conn: \t {{$connected_clients[$k]->socket}]\n\n";
    
                        unset($clients[$key]);
                        unset($recv[$key]);
                        unset($write[$key]);
                        unset($connected_clients[$k]);
                    }
                    break;
                }
                else if ($bytes > 0){
                    $decrypted = $openssl->decrypt_CBC($recv_string);
                    $bytes_msg = mb_strlen($decrypted);
                    $data .= $decrypted;
                }
                else {
                    echo "[\33[91m!\33[0m] general stream_recv() error!\n";
                }
            }
            if( ! empty($data))
            {
                if($all_bytes > BUFFER_LEN){
                    echo "\33[94moverall bytes recieved: ".$all_bytes."\33[0m\n";
                }
                
                if($tunneling === 1){

                    echo "[\33[32m".$ip."\33[0m:\33[35m".$port."\33[0m]\n".$data." => passing to to {$tunneled_addr}\n".DELIMITER."\n";
                    $proxy_res = self::proxy_data_to_target($data, $tunneled_addr);

                    if($proxy_res !== 0){
                        echo "[\33[91m!\33[0m] error proxying data.\n";
                        continue;
                    }
                }
                else {
                    echo "[\33[32m{$ip}\33[0m:\33[92m{$port}\33[0m]\n{$data}\n".DELIMITER."\n";
                    self::write_log("{$ip}:{$port}\n{$data}\n".DELIMITER."\n");
                }
            }
        }
        unset($r_socket);
        return;
    }


    /**
     * 
     * @return string => line
     */
    private static function handle_stdin(array $r, array $w, array $e) : string
    {
        $stdin = fopen('php://stdin', 'r');
        stream_set_blocking($stdin, 0);
        $r = [ $stdin ];
        if(($result = stream_select($r, $w, $e, 0.2, 500000)) !== false){
            if($result === 0) { 
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
     * @return void
     */
    private static function broadcast_line($master, string $line, array $connected_clients, array $write) : void
    {
        if( ! empty($connected_clients) && ! empty($write))
        {
            try {
                $openssl = new OpenSsl;
                $connected_clients = array_values($connected_clients);
                foreach ($write as $k => $w)
                {
                    if($w !== $master->socket) { /** don't write to self */
                        $key = array_search($w,
                                    array_map(function($c) use ($w) {
                                        return ($c->socket === $w) ? $c->socket : null;
                                    }, $connected_clients));
                        // ENCRYPTED WRITE
                        if($connected_clients[$key]->uses_encryption)
                        {
                            $out = $openssl->encrypt_CBC($line);
                            $b = fwrite($w, $out, mb_strlen($out));
                            if( ! $b){
                                echo "[\33[91m!\33[0m] ENCRYPTED: write message to socket error.\n";
                                $r['err'] = 1;
                                continue;
                            }
                        }
                        // DEFAULT WRITE
                        else {
                            $b = fwrite($w, $line, mb_strlen($line));
                            if( ! $b){
                                echo "[\33[91m!\33[0m] write message to socket error.\n";
                                $r['err'] = 1;
                                continue;
                            }
                        }
                        echo "[\33[91m!\33[0m] sent \33[35m{$b}\33[0m bytes to ".
                                 "{$connected_clients[$key]->id}::{$connected_clients[$key]->host}:".
                                 "{$connected_clients[$key]->ip}:{$connected_clients[$key]->port}\n";
                        self::write_log(
                            "sent [{$line}][{$b} bytes] to ".
                            "{$connected_clients[$key]->id}::{$connected_clients[$key]->host}:".
                            "{$connected_clients[$key]->ip}:{$connected_clients[$key]->port}\n"
                        );
                    }
                }
            } catch (\Throwable $th) {
                self::write_log($th->getMessage());
                echo "Oops! Broadcast Error: {$th->getMessage()}\n";
            }
        }
    }


    /**
     * 
     * 
     * @return int => result
     */
    private static function proxy_data_to_target(string $data, string $tunneled_addr) : int
    {
        try {
            $tunnelled_addrarr = explode(":", $tunneled_addr);
    
            $fp = fsockopen($tunnelled_addrarr[0], $tunnelled_addrarr[1], $errno, $errstr, 30); // 30 sec => timeout
            $b = 0; 
    
            if ( ! $fp) {
                echo "$errstr ($errno)\n";
                return 1;
            } else {
                $b = fwrite($fp, $data, mb_strlen($data));
                fclose($fp);
            }

        } catch (\Throwable $th) {
            self::write_log($th->getMessage());
            echo "Oops! ProxySend Error: {$th->getMessage()}\n";
            return 1;
        }

        echo "[\33[91m!\33[0m] proxied \33[35m{$b}\33[0m bytes to {$tunneled_addr}\n";
        return 0;
    }


    /**
     * 
     * @return int => num of written bytes
     */
    private static function write_log(string $msg) : int {
        $ret = file_put_contents(self::LOG, date('Y-m-d H:i:s')." - {$msg}", FILE_APPEND);
        return $ret !== false ? $ret : 0; 
    }


    /**
     * 
     * @return void
     */
    private static function display_clients(array $clients) : void
    {
        echo "\33[94mconnected clients: ".count($clients)."\33[0m\n";

        $clients = array_values($clients); // re-index

        $authoritative_name_servers = null;
        $additional_records = null;

        foreach ($clients as $k => $c) { 

            /*$dns_rec = dns_get_record(
                $c->ip,
                DNS_ANY,
                $authoritative_name_servers,
                $additional_records,
                false // raw => false
            );*/

            echo "[{$k}]: {$c->id} | {$c->host} | {$c->ip}:{$c->port} | {$c->socket}\n";

            /*if( ! empty($dns_rec)){
                echo "DNS info: \n";
                foreach ($dns_rec as $key => $dr) {
                    echo "{$key}: {$dr}\n";
                }
            }*/
        }

        return;
    }
}

?>