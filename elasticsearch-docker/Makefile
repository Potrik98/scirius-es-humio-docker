# Makefile for docker image

.PHONY: build rebuild remove update

IMAGE_NAME=$(shell basename $(PWD) | sed 's/-.*//g')
IMAGE_TAG=multi

build: Dockerfile
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

rebuild: Dockerfile
	docker build --no-cache=true -t $(IMAGE_NAME):$(IMAGE_TAG) .

update:

remove:
	docker image rm $(IMAGE_NAME):$(IMAGE_TAG)
