# CSE508 HW#3 - Plugboard Proxy

pbproxy lets you connect a tcp service to redirect traffic to another pbproxy instance.
pbproxy encrypts the data using aes128 in ctr mode.

<pre>
ssh <--stdin/stdout--> pbproxy-c <--socket 1--> pbproxy-s <--socket 2--> sshd
\______________________________/                \___________________________/
             client                                        server
</pre>

# Author

Paul Campbell <paul.campbell@stonybrook.edu>

# Usage

<pre>
./pbproxy [-l port] -k keyfile destination port

-l  Reverse-proxy mode: listen for inbound connections on &lt;port&gt; and relay
    them to &lt;destination>:&lt;port&gt;

-k  Use the symmetric key contained in &lt;keyfile&gt; (string)
</pre>

# Dependencies

1. make
    * Tested on **GNU Make 4.0**
2. gcc
    * Tested on **gcc (Ubuntu 5.2.1-22ubuntu2) 5.2.1 20151010**
3. openssl
    *  On a Debian based install `sudo apt-get install openssl libssl-dev`

# Build

Type `make` and the program will build the program **pbproxy**.

# Examples

Below is a list of a few test cases for trying out pbproxy

## Example: Proxy to netcat
Open up three terminals

Terminal &#35;1: `nc -l -p 1234`
Terminal &#35;2: `./pbproxy -l 2222 -k sample.key 127.0.0.1 1234`
Terminal &#35;3: `./pbproxy -k sample.key 127.0.0.1 2222`

You can now type in the first terminal and third terminal and see the output.

## Example: Proxy to ssh

Open up two terminals

Terminal &#35;1: `./pbproxy -l 2222 -k sample.key 127.0.0.1 22`
Terminal &#35;2: `ssh -o "ProxyCommand ./pbproxy -k sample.key 127.0.0.1 2222" localhost`

You can now use ssh though **pbproxy**.


# Notes

Used three late days.
