FROM amazonlinux:2017.03

MAINTAINER akrug@mozilla.com

# Patch this image

RUN yum update -y

# Install python 3.6.1

RUN yum install \
    gcc wget findutils \
    zlib zlib-devel openssl-devel \
    libffi-devel git \
    -y

WORKDIR /usr/src/

RUN wget https://www.python.org/ftp/python/3.6.1/Python-3.6.1.tgz

RUN tar xzf Python-3.6.1.tgz

WORKDIR /usr/src/Python-3.6.1

RUN ./configure --enable-optimizations

RUN make install

RUN rm /usr/src/Python-3.6.1.tgz

# Install pip

WORKDIR /root

RUN wget https://bootstrap.pypa.io/get-pip.py

RUN chmod +x get-pip.py

RUN python get-pip.py

RUN pip install awscli

RUN pip install awsmfa

RUN curl --silent --location https://rpm.nodesource.com/setup_6.x | bash -

RUN yum -y install nodejs

RUN npm install -g serverless

RUN npm install -g serverless-python-requirements

RUN mkdir /workspace

WORKDIR /workspace

RUN yum clean all
