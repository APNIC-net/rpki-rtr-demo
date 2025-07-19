FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update -y
RUN apt-get install -y build-essential
RUN apt-get install -y sudo
COPY . /root/rpki-rtr-demo
WORKDIR /root/rpki-rtr-demo
RUN ./docker-prep.sh
ENTRYPOINT ["/bin/bash"]
