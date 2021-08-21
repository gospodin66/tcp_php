<?php namespace App\Models;

class Master {

    public $socket;
    public string $addr;
    public int $port;
    private $context;

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

        /*($this->socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP))
        || die("[\33[91m!\33[0m] socket_create() error: "
                .socket_strerror(socket_last_error())."\n");*/
    }

    /*public function _listen(){
        (socket_listen($this->socket))
        || die("[\33[91m!\33[0m] socket_listen() error: "
                .socket_strerror(socket_last_error($this->socket))."\n");
    }


    public function _bind(){
        (socket_bind($this->socket, $this->addr, $this->port))
        || die("[\33[91m!\33[0m] socket_bind() error: "
                .socket_strerror(socket_last_error($this->socket))."\n");
    }

    public function _set_opts(){
        socket_set_nonblock($this->socket);
        socket_set_option($this->socket, SOL_SOCKET, SO_REUSEADDR, 1);
    }*/

}