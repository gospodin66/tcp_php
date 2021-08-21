<?php namespace App\Models;

class IncClient {

    public $id;
    public $host;
    public $ip;
    public $port;
    public $socket;
    public $connection_status;
    public $ttl;

    public function __construct($socket){
        $ipport = stream_socket_get_name($socket, true);
        $ip = substr($ipport, 0, strpos($ipport, ':'));
        $port = substr($ipport, strpos($ipport, ':') +1, strlen($ipport));
        
        $this->id = strtoupper(bin2hex(random_bytes(8)));
        $this->ip = $ip;
        $this->port = $port;
        $this->host = gethostbyaddr($ip);
        $this->socket = $socket;
        $this->connection_status = true;
        $this->ttl = 0;
    }


    private function generate_metadata(){
        $openssl_enc_dec = new OpenSSL_Enc_Dec;
        $token = bin2hex(openssl_random_pseudo_bytes(16));
        
        if(false === ($tokenhash = $openssl_enc_dec->generate_keypair('master', $token))){
            return false;
        }
        if(false === ($AESKey = $openssl_enc_dec->fetch_key())){
            return false;
        }
        if(false === ($RSAKeyStrings = $openssl_enc_dec->get_keypair_strings())){
            return false;
        }
    
        $RSAPubStripped = str_replace('-----BEGIN PUBLIC KEY-----', '', $RSAKeyStrings['public']);
        $RSAPubStripped = str_replace('-----END PUBLIC KEY-----', '', $RSAPubStripped);
        
        if(false === ($encryptedAESKey = $openssl_enc_dec->encryptRSA($token, $AESKey, 'private'))){
            return false;
        }
    
        $glued = $encryptedAESKey.$RSAPubStripped;
        if(false === openssl_sign($glued, $signature, $RSAKeyStrings['private'], OPENSSL_ALGO_SHA512)){
            echo "Error generating signature.\n";
            return false;
        }
    
        $base64glued = base64_encode($signature.$glued);
        unset($openssl_enc_dec);
    
        return (1 === openssl_verify($glued, $signature, $RSAKeyStrings['public'], OPENSSL_ALGO_SHA512))
                ? ['token' => $token, 'base64glued' => $base64glued]
                : false;
    }

}