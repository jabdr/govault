#!/bin/bash
mkdir -p tests/ssl
openssl req -x509 -newkey rsa:4096 -keyout tests/ssl/key.pem -out tests/ssl/certs.pem -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
