# tcp_php
<p>tcp server - clients implementation using stream_socket_server()</p>

<h5>Via ssh tunnel</h5>
<p>local_machine:$ ssh -L 7171:localhost:7272 remote_user@remote_addr</p>
<p>remote_machine:$ ./server 7272</p>
<p>local_machine:$ ./client 127.0.0.1 7171</p>
