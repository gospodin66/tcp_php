# tcp_php
tcp server - clients implementation using stream_socket_server()

local_machine:$ ssh -L 7171:localhost:7272 remote_user@remote_addr
remote_machine:$ ./server 7272
local_machine:$ ./client 127.0.0.1 7171
