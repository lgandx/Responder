#!/bin/bash
openssl genrsa -out certs/responder.key 2048
openssl req -new -x509 -days 3650 -key certs/responder.key -out certs/responder.crt -subj "/"
