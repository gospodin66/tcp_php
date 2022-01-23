<?php namespace App\Encrypt;

class OpenSsl {
    
    private const CYPHER = 'AES-256-CBC';
    private const OPTIONS = OPENSSL_RAW_DATA;
    private const HASH_ALGO = 'sha256';
    private const HASH_LEN = 32;
    private const PRIVATE_KEY_LENGTH = 4096;
    private const CRYPTO_HASH_ALGO_256 = 'sha256';
    private const CRYPTO_HASH_ALGO_512 = 'sha512';

    /**
     * 
     * @return base64key => string read from .env
     */
    public function fetch_CBC_key() : string {
        if(file_exists('../.env') === false){
            echo "[\33[91m!\33[0m] crypto-key not found.\n";
        }
        else { 
            if(($env = file_get_contents("../.env")) === false){
                echo '[\33[91m!\33[0m] error reading crypto-key.';
                return "";
            }
            // '=' is part of base64 => use '::' as delimiter in .env
            if(empty($env)){
                $key = base64_encode(openssl_random_pseudo_bytes(32));
                file_put_contents("../.env", "CBC_KEY::{$key}");
                echo "[\33[91m!\33[0m] new key [{$key}] saved to .env\n";
            }
            else {
                $extracted_key = explode("\n", $env);
                $key = explode("::", $extracted_key[0])[1];
            }
            return $key;
        }
        return "";
    }

    public function generate_keypair(string $user) : bool {

        if(empty($user)){
            $user = 'master';
        }
        
        $keys_dir     = "../keys";
        $private_path = "$keys_dir/$user/private.pem";
        $public_path  = "$keys_dir/$user/public.pem";
        
        $privateKeyString = file_exists($private_path) ? file_get_contents($private_path) : null;
        $publicKeyString  = file_exists($public_path)  ? file_get_contents($public_path)  : null;
        
        // generate keypair if !exists
        if(empty($privateKeyString) || empty($publicKeyString))
        {
            $keyPair = openssl_pkey_new([
                "digest_alg" => self::CRYPTO_HASH_ALGO_512,
                "private_key_bits" => self::PRIVATE_KEY_LENGTH,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ]);
            
            openssl_pkey_export($keyPair, $privateKeyString);
            
            $keyDetails      = openssl_pkey_get_details($keyPair);
            $publicKeyString = $keyDetails["key"];
            
            if( ! file_exists("$keys_dir/$user")){
                if( ! mkdir("$keys_dir/$user", 0755, true)){
                    echo "mkdir() user-dir error.";
                    return false;
                }
            }
            
            if(file_put_contents($private_path, $privateKeyString) === false
             || file_put_contents($public_path, $publicKeyString) === false)
            {
                echo "Keypair store error.";
                return false;
            }
        }
        
        return true;
    }

    public function get_keypair(string $user, string $token) : array {

        if(empty($user)){
            $user = 'master';
        }

        $keys_dir     = "../keys";
        $private_path = "$keys_dir/$user/private.pem";
        $public_path  = "$keys_dir/$user/public.pem";
        
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : null;
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : null;

        if(empty($privateKeyString) || empty($publicKeyString)) { return []; }

        if(false === ($publicKey = openssl_pkey_get_public([$publicKeyString, $token]))) {
            echo "Malformed public key.\n";
            return [];
        }
        if(false === ($privateKey = openssl_pkey_get_private([$privateKeyString, $token]))) {
            echo "Malformed private key.\n";
            return [];
        }

        return ['public' => $publicKey, 'private' => $privateKey];
    }

    public function get_keypair_strings(string $user) : array {

        if(empty($user)){
            $user = 'master';
        }
        
        $keys_dir     = "../keys";
        $private_path = "$keys_dir/$user/private.pem";
        $public_path  = "$keys_dir/$user/public.pem";
        
        $privateKeyString = file_exists($private_path) ? trim(file_get_contents($private_path)) : null;
        $publicKeyString  = file_exists($public_path)  ? trim(file_get_contents($public_path))  : null;

        if(empty($privateKeyString) || empty($publicKeyString)) { return []; }

        return ['public' => $publicKeyString, 'private' => $privateKeyString];
    }

    public function generate_metadata(&$client) :? string {
        
        $id = "{$client->host}_{$client->ip}";

        if( ! $this->has_keypair($id)){
            if( ! $this->generate_keypair($id)){
                return null;
            }
        }

        if(false === ($RSAKeyStrings = $this->get_keypair_strings($id))){
            return null;
        }

        if(false === ($AESKey = $this->fetch_CBC_key())){
            return null;
        }
    
        $RSAPubStripped = str_replace('-----BEGIN PUBLIC KEY-----', '', $RSAKeyStrings['public']);
        $RSAPubStripped = str_replace('-----END PUBLIC KEY-----', '', $RSAPubStripped);
        
        if(false === ($encryptedAESKey = $this->encryptRSA($client->token, 'private', $AESKey, $id))){
            return null;
        }
    
        $glued = $encryptedAESKey.$RSAPubStripped;

        // produces $signature var
        if(false === openssl_sign($glued, $signature, $RSAKeyStrings['private'], OPENSSL_ALGO_SHA512)){
            echo "[\33[91m!\33[0m] error generating signature.\n";
            return null;
        }

        // base64glued => signature.encrypted_aes_key.rsa_key_stripped
        $base64glued = base64_encode($signature.$glued);
    
        return  (1 === openssl_verify(
                          $glued,
                          $signature,
                          $RSAKeyStrings['public'],
                          OPENSSL_ALGO_SHA512
                       )
                ) ? $base64glued : null;
    }

    public function has_keypair(string $user) : bool {

        $keys_dir     = "../keys";
        $private_path = "{$keys_dir}/{$user}/private.pem";
        $public_path  = "{$keys_dir}/{$user}/public.pem";

        if(file_exists($public_path) === false
        || file_exists($private_path) === false){
            echo "\n[\33[91m!\33[0m] crypto-key not found for {$user}.\n";
            return false;
        }
        else { 
            if(($public = file_get_contents($public_path)) === false
            || ($private = file_get_contents($private_path)) === false)
            {
                echo "\n[\33[91m!\33[0m] error reading keypair for {$user}\n";
                return false;
            }
        }
        return (!empty($public) && !empty($private));
    }

    /**
     * 
     * @param token  => passphrase for encryption
     * @param data   => data to encrypt
     * 
     * @return string
     */
    public function encryptRSA(
        string $token,
        string $keytype,
        $data,
        string $client
    ) : string
    {
        if(false === ($keypair = self::get_keypair($client, $token))){
            echo "[\33[91m!\33[0m] error fetching RSA key.\n";
            return "";
        }

        if($keytype === 'public'){
            if(false === openssl_public_encrypt($data, $encryptedWithPublic, $keypair['public'])) {
                echo "[\33[91m!\33[0m] error encrypting with public key.\n";
                return "";
            }
            openssl_free_key($keypair['public']);
        }
        else if($keytype === 'private'){
            if(false === openssl_private_encrypt($data, $encryptedWithPrivate, $keypair['private'])) {
                echo "[\33[91m!\33[0m] error encrypting with private key.\n";
                return "";
            }
            openssl_free_key($keypair['private']);
        }
        else {
            echo "[\33[91m!\33[0m] invalid key type.\n";
        }

        unset($data);

        return (($keytype === 'public')
                ? base64_encode($encryptedWithPublic)
                : (($keytype === 'private')
                ? base64_encode($encryptedWithPrivate)
                : false)); 
    }

    /**
     * 
     * @param token => passphrase for encryption
     * @param encryptedb64 => data to decrypt
     * @param keytype => public|private
     * 
     * @return string
     */
    public function decryptRSA(
        string $token,
        string $keytype,
        string $encryptedb64,
        string $client
    ) : string
    {
        $decrtypted = "";

        if(empty($keytype)){
            $keytype = 'public';
        }

        if(false === ($keypair = self::get_keypair($client, $token))){
            echo "[\33[91m!\33[0m] error fetching RSA key.\n";
            return "";
        }
        
        $encrypted = base64_decode($encryptedb64);

        if($keytype === 'public'){
            if( ! openssl_public_decrypt($encrypted, $decrtypted, $keypair['public'])) {
                echo "[\33[91m!\33[0m] error decrypting with public key what was encrypted with private key\n";
                return "";
            }
            openssl_free_key($keypair['public']);
        }
        else if($keytype === 'private'){
            if( ! openssl_private_decrypt($encrypted, $decrtypted, $keypair['private'])) {
                echo "[\33[91m!\33[0m] error decrypting with private key what was encrypted with public key\n";
                return "";
            }
            openssl_free_key($keypair['private']);
        }
        else {
            echo "[\33[91m!\33[0m] invalid key type.\n";
        }
        

        return $decrtypted;
    }


    public function encrypt_CBC(string $clrtext) :? string {
        if(($base64key = self::fetch_CBC_key()) === ""){
            return null;
        }
        $key = base64_decode($base64key);
        try {
            $ivlen = openssl_cipher_iv_length(self::CYPHER);
            $iv = openssl_random_pseudo_bytes($ivlen);
            $ciphertext = openssl_encrypt($clrtext, self::CYPHER, $key, self::OPTIONS, $iv);
            $hmac = hash_hmac(self::HASH_ALGO, $iv.$ciphertext, $key, true);
            return base64_encode($iv.$hmac.$ciphertext);
        } catch (\Throwable $e){
            throw $e;
            return null;
        }
        return null;
    }
    public function decrypt_CBC(string $enc) :? string {
        if(empty($enc)){ return null; }
        if(($base64key = self::fetch_CBC_key()) === ""){ return null; }
        if(false === ($encrypted = base64_decode($enc))) { return null; }
        if(false === self::is_binary($encrypted)) { return null; }
        if(false === ($key = base64_decode($base64key))) { return null; }
        try {
            $ivlen = openssl_cipher_iv_length(self::CYPHER);
            $iv = substr($encrypted, 0, $ivlen);
            $hmac = substr($encrypted, $ivlen, self::HASH_LEN);
            $ciphertext = substr($encrypted, ($ivlen + self::HASH_LEN));
            if(false === ($clrtext = openssl_decrypt($ciphertext, self::CYPHER, $key, self::OPTIONS, $iv))){
                return null;
            }
            $calcmac = hash_hmac(self::HASH_ALGO, $iv.$ciphertext, $key, true);
            if(function_exists('hash_equals')) {
                if (hash_equals($hmac, $calcmac)){ return $clrtext; }
            } else { 
                if ($this->hash_equals_custom($hmac, $calcmac)){  return $clrtext; }
            }
        } catch (\Throwable $e){
            throw $e;
            return null;
        }
        return null;
    }

    /**
     * helper fn()
     */
    private static function is_binary(string $s) : bool {
        return ( ! ctype_print($s)) ? true : false;
    }
    

    /**
     * (Optional)
     * hash_equals() function polyfilling.
     * PHP 5.6+ timing attack safe comparison
     */
    private function hash_equals_custom($knownString, $userString) {
        if (function_exists('mb_strlen')) {
            $kLen = mb_strlen($knownString, '8bit');
            $uLen = mb_strlen($userString, '8bit');
        } else {
            $kLen = strlen($knownString);
            $uLen = strlen($userString);
        }
        if ($kLen !== $uLen) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $kLen; $i++) {
            $result |= (ord($knownString[$i]) ^ ord($userString[$i]));
        }
        return (0 === $result);
    }
}
?>