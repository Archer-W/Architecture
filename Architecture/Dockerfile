FROM ubuntu:16.04

MAINTAINER Ovidiu Dan <contact@ovidiudan.com>

RUN apt-get update && apt-get install -y \
    cython3 \
    gcc \
    ipython3-notebook \
    mc \
    nano \
    python3 \
    python3-numpy \
    python3-pip \
    python3-setuptools \
    python3-scipy \
    vim \
    linux-tools-common \
    linux-tools-`uname -r` \
    linux-cloud-tools-`uname -r` \
    linux-tools-generic \
    linux-cloud-tools-generic

RUN pip3 install -U gensim

WORKDIR /Architecture
ADD . /Architecture

#CMD ["ipython3","throughput.py"]

