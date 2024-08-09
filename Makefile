TAG := latest
CONTAINER_REPO ?= syscall_count
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format

export IG_EXPERIMENTAL = true

.PHONY: build-gadget
build-gadget:
	sudo -E ig image build \
		-t $(CONTAINER_REPO):$(IMAGE_TAG) \
		--update-metadata gadget/

.PHONY: export-gadget
export-gadget:
	sudo -E ig image export \
		$(CONTAINER_REPO):$(IMAGE_TAG) \
		$(CONTAINER_REPO).tar
	
.PHONY: build
build: build-gadget export-gadget
	go build .

.PHONY: run
run:
	sudo ./syscall_count

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: lint
golint:
	golint ./...

.PHONY: run-gadget
run-gadget:
	sudo -E ig run $(CONTAINER_REPO):$(IMAGE_TAG) $$PARAMS

.PHONY: clang-format
clang-format:
	$(CLANG_FORMAT) -i gadget/program.bpf.c
