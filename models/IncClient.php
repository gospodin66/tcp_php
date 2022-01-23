<?php namespace App\Models;

class IncClient {

    public string $id;
    public string $host;
    public string $ip;
    public int $port;
    public $socket;
    public bool $connection_status;
    public int $ttl;
    public bool $uses_encryption;
    public string $token;

    public function __construct($socket, bool $uses_encryption)
    {
        $ipport = stream_socket_get_name($socket, true);
        $ip = substr($ipport, 0, strpos($ipport, ':'));
        $port = substr($ipport, strpos($ipport, ':') +1, strlen($ipport));
        
        $this->id = strtoupper(bin2hex(openssl_random_pseudo_bytes(8)));
        $this->ip = $ip;
        $this->port = $port;
        $this->host = gethostbyaddr($ip) ?? "unknown";
        $this->socket = $socket;
        $this->connection_status = true;
        $this->ttl = 0;
        $this->uses_encryption = $uses_encryption;
        $this->token = ($this->uses_encryption) ? bin2hex(openssl_random_pseudo_bytes(16)) : "";
    }

}