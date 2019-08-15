# Makefile for docker image

# up takes optional arguments
ifeq (up,$(firstword $(MAKECMDGOALS)))
	UP_ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
	$(eval $(UP_ARGS):;@:)
endif

.PHONY: help sysctls up build

help:
	@ echo "Available commands"
	@ echo "  build              build the docker containers"
	@ echo "  up [args...]       docker-compose up"
	@ echo "  setup-scirius      install scirius to scirius/docker using scirius-autosetup"
	@ echo "  sysctls            set sysctl settings (needed for elasticsearch)"

setup-scirius:
	(git clone git@github.com:jorgenbele/scirius-autosetup && pipenv --python 2 && pipenv run $(MAKE) SCIRIUS_GIT_BRANCH=develop SCIRIUS_DIR='../scirius-docker/scirius' -C scirius-autosetup init)

build:
	(cd scirius-docker && sh make_dockerfile.sh)
	docker-compose build

up:
	docker-compose up ${UP_ARGS}

sysctls:
	sudo sysctl -w vm.max_map_count=262144

reset-all:
	docker-compose down
	sudo rm -rf data
