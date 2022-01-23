<?php namespace App\Models;

class ClientStream {

    public $socket;
    public string $addr;
    public int $port;
    
    public function __construct(
        string $addr,
        int $port,
    )
    {
        $this->addr = $addr;
        $this->port = $port;

        $context = stream_context_create();
        $this->socket = stream_socket_server(
            "{$this->addr}:{$this->port}",
            $errno,
            $errstr, 
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
            $context
        );

        if ( ! $this->socket){
            echo "Error $errno creating stream: $errstr";
            exit(1);
        }


    }
}