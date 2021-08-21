<?php namespace App\Models;

class Master {

    public $socket;
    public string $addr;
    public int $port;
    private $context;

    /** 
     * $ php -r "echo base64_encode(openssl_random_pseudo_bytes(32));" > .env 
     * 
     * SOCKET/STREAM SELECT
     * --------------------------------------------
     * tv_sec  - num of seconds		 - 0.2
     * tv_usec - num of microseconds - 500000 = 0.5
     * --------------------------------------------
     */
    
    public function __construct(string $addr, int $port){
        $this->addr = $addr;
        $this->port = $port;

        $this->context = stream_context_create();
        $this->socket = stream_socket_server(
            "{$this->addr}:{$this->port}",
            $errno,
            $errstr, 
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
            $this->context
        );

        if ( ! $this->socket) {
            echo "Error $errno creating stream: $errstr";
            exit(1);
        }
    }
}