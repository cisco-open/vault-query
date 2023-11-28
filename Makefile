LOCAL_BUILD_PATH=./bin
builder=podman # can be docker
INSTALL_PATH=/usr/local/bin
VERSION=0.1.9

default: all

swagger:
	@echo "This requires goswagger (https://goswagger.io/) to be installed"
	swagger generate client -c pkg/apiclinet
	swagger generate server --server-package=pkg/apiserver --main-package=server

build-server:
	GO_ENABLED=0 go build -ldflags="-w -s -X=vaultquery/pkg/apiserver.version=$(VERSION)" -o $(LOCAL_BUILD_PATH)/vq-server ./cmd/server/

build-client:
	GO_ENABLED=0 go build -ldflags="-w -s -X=main.version=$(VERSION)" -o $(LOCAL_BUILD_PATH)/vq ./cmd/client/

.PHONY: install-client
install-client: build-client
	cp ./bin/vq $(INSTALL_PATH)/vq
	mkdir -p ~/.config/vault-query
	cp ./defaults.yaml ~/.config/vault-query/config.yaml

.PHONY: run-server
run-server: build-server
	./bin/vq-server --port=51250

.PHONY: vault
vault:
	$(builder) run --cap-add=IPC_LOCK -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' -p 0.0.0.0:8200:8200 vault

.PHONY: image
image:
	@echo "Building docker image for server"
	$(builder) buildx build -f Dockerfile-Server -t vq-server:dev-$(VERSION) .

.PHONY: all
all: build-client build-server image

clean:
	rm -rf $(LOCAL_BUILD_PATH)
