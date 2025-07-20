FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y
RUN apt-get install -y build-essential sudo
COPY ./docker-prep.sh .
RUN ./docker-prep.sh
COPY ./docker-mkcert.sh .
RUN ./docker-mkcert.sh
COPY ./docker-rtrlib.sh .
RUN ./docker-rtrlib.sh
COPY . /root/rpki-rtr-demo
WORKDIR /root/rpki-rtr-demo
RUN sudo cpanm -v --installdeps .
RUN sudo make clean || true
RUN perl Makefile.PL && make
ENTRYPOINT ["/bin/bash"]
