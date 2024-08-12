TAG := latest
CONTAINER_REPO ?= syscall_count
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format

export IG_EXPERIMENTAL = true

.PHONY: build-gadget
build-gadget:
	sudo -E ig image build \
		-t $(CONTAINER_REPO):$(IMAGE_TAG) \
		gadget/

.PHONY: export-gadget
export-gadget:
	sudo -E ig image export \
		$(CONTAINER_REPO):$(IMAGE_TAG) \
		$(CONTAINER_REPO).tar
	
.PHONY: generate-syscall-compat
generate-syscall-compat:
	mkdir -p ./gadget/syscalls
	docker run --rm -v ./gadget/syscalls:/libs/driver falcosecurity/syscalls-bumper:latest
	mv ./gadget/syscalls/syscall_compat_x86_64.h ./gadget/syscall_compat_x86_64.h
	mv ./gadget/syscalls/syscall_compat_aarch64.h ./gadget/syscall_compat_aarch64.h
	rm -rf ./gadget/syscalls
	
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
