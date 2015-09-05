# Run CryptCheck with Docker

## Prerequisites

* Docker 1.8

## Getting the image

You may pull the image from the Docker Hub:

```
docker pull aeris/cryptcheck
```

or build the image by your own:

```
docker build -t aeris/cryptcheck .
```

## Usage

```
docker run --rm -t aeris/cryptcheck bin/check_https example.com
docker run --rm -t aeris/cryptcheck bin/check_smtp example.com
docker run --rm -t aeris/cryptcheck bin/check_ssh example.com
docker run --rm -t aeris/cryptcheck bin/check_xmpp example.com
```
