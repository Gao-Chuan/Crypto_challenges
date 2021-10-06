FROM fedora:34

WORKDIR /crypto/

COPY target/release/bls_mps /crypto/
COPY flag.txt /crypto/

EXPOSE 10086

CMD ["/crypto/bls_mps"]
