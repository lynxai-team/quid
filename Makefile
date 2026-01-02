help:
	# make all         Build frontend, backend and doc site
	# make build       Build the frontend UI
	# make quid        Build the backend (Go)
	# make doc         Build the documentation site
	#
	# make run         Run the backend (Go serves the static files)
	# make front       Run the frontend in dev mode (Node serves the frontend)
	# make run-doc     Run the docs site frontend in dev mode (Node serves the frontend)
	# make vet         Audit TypeScript and Go code & dependencies
	#
	# make compose-up  Run Quid and Database using podman-compose or docker-compose
	# make compose-rm  Stop and remove containers
	#
	# make up          Upgrade dependencies patch version
	# make up+         Upgrade dependencies minor version
	#
	# make fmt     Go: Generate code and Format code
	# make test    Go: Check build and Test
	# make cov     Go: Browse test coverage
	#
	# Before "git push" the backend:
	#
	#     make up-go fmt test vet-go


.PHONY: all
all: build quid doc


.PHONY: build
build: ui/dist


ui/dist: ui/node_modules ui/package-lock.json $(shell find ui/src -type f) $(shell test ! -d ui/node_modules || find ui/node_modules -iname '*test*' -prune -o -name *.[jt]s -type f -print)
	cd ui && npm run build

ui/node_modules/*/*:  ui/package-lock.json
ui/node_modules/*:    ui/package-lock.json
ui/node_modules:      ui/package-lock.json
ui/package-lock.json: ui/package.json
ui/node_modules       ui/package-lock.json:
	cd ui && npm run build

.PHONY: front
front:
	cd ui && npm i --prefer-offline --no-audit --no-fund && npm run dev

.PHONY: run-doc
run-doc:
	cd docsite && npm i --prefer-offline --no-audit --no-fund && npm run dev

.PHONY: doc
doc:
	cd docsite && npm i --prefer-offline --no-audit --no-fund && npm run build_to_gh

.PHONY: run
run: go.sum $(shell find -name *.go)
# CGO_ENABLED=1 GOFLAGS="-trimpath -modcacherw" GOLDFLAGS="-d -s -w -extldflags=-static" go run -a -tags osusergo,netgo -installsuffix netgo ./cmd/quid -dev -v
	go run ./cmd/quid -dev -v

quid: go.sum $(shell find -name *.go)
	CGO_ENABLED=0 GOFLAGS="-trimpath -modcacherw" GOLDFLAGS="-d -s -w -extldflags=-static" go build -a -tags osusergo,netgo -installsuffix netgo -o $@ ./cmd/quid

go.sum: go.mod
	go mod tidy
	go mod verify


define help

## Install Podman or Docker

Podman and Docker should be both supported.
Four options to setup your container engine:

1. Install `podman` and `podman-compose` (Python)

      sudo apt install podman-compose

2. Install `docker` and `docker-compose` v1 (Python)

   The `docker` version provided by your distro is more reviewed.
   But does not yet install the `compose` plugin v2 (only the old v1).

      sudo apt install docker-compose

3. Install plugin `compose` v2 (Go) in hybrid mode.

      sudo apt install docker.io curl ca-certificates
      mkdir -pv ~/.docker/cli-plugins
      curl -SL https://github.com/docker/compose/releases/download/v2.27.1/docker-compose-linux-x86_64 -o ~/.docker/cli-plugins/docker-compose
      chmod +x ~/.docker/cli-plugins/docker-compose
      docker compose version

4. Install both `docker` and `compose` v2 (Go) from docker.com (and also `buildx`)

      sudo apt purge --purge --autoremove "docker*"" podman-docker containerd runc

  Follow https://docs.docker.com/engine/install  
  Use the `apt` repository:
  https://docs.docker.com/engine/install/debian/#install-using-the-repository

  Finally:

      sudo apt install docker-compose-plugin docker-buildx-plugin
      docker compose version

### Enable Docker

    sudo systemctl enable docker.service
    sudo service docker start

### Add current user to docker group

If you want to just type `docker` instead of `sudo docker`,
check if you are in the `docker` group:

    $ groups   # or "id -nG"
    you adm cdrom sudo dip plugdev lpadmin sambashare

If `docker` is missing, enter commands:

    sudo usermod -aG docker $USER
    # or
    sudo adduser $USER docker

login again in a sub-shell (or you must log out from your Desktop session)

    su - $USER

Check again:

    $ groups   # or "id -nG"
    you adm cdrom sudo dip plugdev lpadmin sambashare docker

You may need to start the Docker daemon if not automatically started at boot time:

    $ sudo systemctl start docker

    $ sudo systemctl status docker
    ● docker.service - Docker Application Container Engine
    Loaded: loaded (/usr/lib/systemd/system/docker.service; disabled; vendor preset: disabled)
    Active: active (running) since Wed 2019-06-05 18:08:07 CEST; 1min 48s ago
        Docs: https://docs.docker.com
    Main PID: 12034 (dockerd)
        Tasks: 25
    Memory: 508.9M
    CGroup: /system.slice/docker.service
            └─12034 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
endef

export help


.PHONY: compose-up
compose-up:
	@export DOCKER_BUILDKIT=1          ; \
	export COMPOSE_DOCKER_CLI_BUILD=1  ; \
	{ command -v podman-compose                         && ( set -x && podman-compose -f compose.yml up --build -d ) ; } || \
	{ command -v docker-compose                         && ( set -x && docker-compose -f compose.yml up --build -d ) ; } || \
	{ command -v docker && docker help|grep -wq compose && ( set -x && docker compose -f compose.yml up --build -d ) ; } || \
	{ echo "$$help"; false; }

	# Open browser on localhost:8090 if Quid is running
	@{ command -v podman && (set -x && podman ps -qf name=quid) || (set -x && docker ps -qf name=quid) ; } | \
	grep -s . && xdg-open http://localhost:8090

	# Default web login:
	#    namespace = Quid
	#    username  = admin
	#    password  = myAdminPassword

	# Print containers logs. [Ctrl+C] to stop the logs printing.
	@{ command -v podman-compose                         && ( set -x && podman-compose -f compose.yml logs --follow ) ; } || \
	{  command -v docker-compose                         && ( set -x && docker-compose -f compose.yml logs --follow ) ; } || \
	{  command -v docker && docker help|grep -wq compose && ( set -x && docker compose -f compose.yml logs --follow ) ; }

.PHONY: compose-rm
compose-rm:
	{ command -v podman-compose                         && set -x && podman-compose -f compose.yml ps -q  | xargs podman stop && \
	                                                                 podman-compose -f compose.yml ps -aq | xargs podman rm;} || \
	{ command -v docker-compose                         && set -x && docker-compose -f compose.yml down                    ;} || \
	{ command -v docker && docker help|grep -wq compose && set -x && docker compose -f compose.yml down                    ;}


.PHONY: vet
vet: vet-ui vet-go

.PHONY: vet-ui
vet-ui:
	cd ui && npm i --prefer-offline --no-audit --no-fund && npm audit --all --recursive

.PHONY: vet-go
vet-go:
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --fix || true
	$(MAKE) run


.PHONY: up up+
up:  up-ui up-go
up+: up+ui up+go

.PHONY: up-ui
up-ui:
	@echo TODO
	# cd ui && npm i --prefer-offline --no-audit --no-fund && npm ??????
	# { yarn    && yarn    up --interactive --caret; } || \
	# { yarnpkg && yarnpkg up --interactive --caret; }
	# flag --caret prepends the new version with "^" allowing upgrading the minor number

.PHONY: up+ui
up+ui:
	@echo TODO
	# cd ui && \
	# { yarn    && yarn    up --interactive --tilde; } || \
	# { yarnpkg && yarnpkg up --interactive --tilde; }
	# flag --tilde prepends the new version with "~" that limits vanilla upgrade to patch only

.PHONY: up-go
up-go: go.sum
	GOPROXY=direct go get -t -u=patch all
	go mod tidy

.PHONY: up+go
up+go: go.sum
	go get -t -u all
	go mod tidy


.PHONY: fmt
fmt:
	go generate ./...
	go run mvdan.cc/gofumpt@latest -w -extra -l -lang go1.25 .


.PHONY: test
test:
	go build ./...
	go test -race -vet all -run=. -bench=. -benchmem -benchtime 10ms -tags=quid -coverprofile=code-coverage.out ./...


.PHONY: cov
cov: code-coverage.out
	go tool cover -html code-coverage.out

code-coverage.out: go.sum $(shell find -name *.go)
	go test -race -vet all -run=. -bench=. -benchmem -benchtime 10ms -tags=quid -coverprofile=code-coverage.out ./...
