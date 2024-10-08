TAG := latest
CONTAINER_REPO ?= ghcr.io/dorser/syscall-count
IMAGE_TAG ?= $(TAG)
CLANG_FORMAT ?= clang-format

.PHONY: build-gadget
build-gadget:
	sudo -E ig image build \
		-t $(CONTAINER_REPO):$(IMAGE_TAG) \
		--update-metadata gadget/

.PHONY: generate-syscall-compat
generate-syscall-compat:
	mkdir -p ./gadget/syscalls
	docker run --rm -v ./gadget/syscalls:/libs/driver falcosecurity/syscalls-bumper:latest
	mv ./gadget/syscalls/syscall_compat_x86_64.h ./gadget/syscall_compat_x86_64.h
	mv ./gadget/syscalls/syscall_compat_aarch64.h ./gadget/syscall_compat_aarch64.h
	rm -rf ./gadget/syscalls
	
.PHONY: build
build: build-gadget
	
.PHONY: run
run: run-gadget

.PHONY: run-gadget
run-gadget:
	sudo -E ig run $(CONTAINER_REPO):$(IMAGE_TAG) $$PARAMS

.PHONY: clang-format
clang-format:
	find gadget/ -name '*.c' -o -name '*.h' | xargs $(CLANG_FORMAT)  -i
