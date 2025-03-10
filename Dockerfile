FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -y && \
    apt -y --no-install-recommends \
    install tzdata build-essential make wget tar g++ gcc git libssl-dev ca-certificates \
    lsb-release software-properties-common gnupg libmpc-dev

#WORKDIR /
#RUN wget https://ftp.tsukuba.wide.ad.jp/software/gcc/releases/gcc-14.2.0/gcc-14.2.0.tar.gz
#RUN tar -xzvf gcc-14.2.0.tar.gz
#WORKDIR /gcc-14.2.0
#RUN ./configure --prefix=/usr/local --enable-languages=c,c++ --disable-multilib && make && make install

WORKDIR /
# download cmake source
RUN wget https://cmake.org/files/v3.30/cmake-3.30.0.tar.gz
RUN tar -zxvf cmake-3.30.0.tar.gz
# install go toolchain
RUN wget https://dl.google.com/go/go1.24.1.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.24.1.linux-amd64.tar.gz
ENV PATH=/usr/local/go/bin:$PATH
RUN go version
# install clang tools
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh
RUN ./llvm.sh 19 all

# build cmake
WORKDIR /cmake-3.30.0
RUN ./configure
RUN make && make install

# build por lib and web api
WORKDIR /PoR
COPY . .
RUN make por_lib
RUN make por_lib_test
RUN make por_service

CMD ["./app/por_web_api", "-p", "./app/eight_users.txt"]