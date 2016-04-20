# BUILD: docker build -t rfdrake/locfg .
# RUN:   docker run rfdrake/locfg

FROM debian:jessie

ENV DEBIAN_FRONTEND noninteractive
RUN echo "deb-src http://httpredir.debian.org/debian/ jessie main non-free contrib" >> /etc/apt/sources.list.d/jessie.list
RUN apt-get update && apt-get install -y \
    perl \
    libio-socket-ssl-perl \
    libsocket6-perl \
    libterm-readkey-perl

RUN apt-get -y build-dep openssl
RUN apt-get -y source openssl
RUN apt-cache show openssl > /openssl-version

RUN UPVER=$(awk '$1 == "Version:" { split($2,a1,/\-/); print a1[1] }' /openssl-version); \
    cd openssl-${UPVER}; sed --in-place 's/no-ssl3//g' debian/rules; dpkg-buildpackage -b -us -uc;

RUN SSLVER=$(awk '$1 == "Version:" { print $2 }' /openssl-version); \
    dpkg -i /libssl1.0.0_${SSLVER}_amd64.deb /openssl_${SSLVER}_amd64.deb

ADD locfg.pl /locfg.pl
ADD . /ilo
WORKDIR /ilo

ENTRYPOINT ["/locfg.pl"]
CMD ["-h"]

