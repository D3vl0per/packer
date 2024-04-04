CGO=1
GOOS=linux
GOARCH=amd64
GOFLAGS="-buildmode=pie -trimpath -mod=readonly -modcacherw"
TAGS="osusergo,netgo,static_build"
LDFLAGS='-linkmode external -s -w -extldflags "-static-pie"'

install: golangci-lint-install

dep:
	go mod download

build-cgo:
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOFLAGS=$(GOFLAGS) go build -o packer -tags $(TAGS) -ldflags $(LDFLAGS) -v ./cmd/...
	chmod +x packer

lint:
	golangci-lint run

golangci-lint-install:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.55.0

check-build-flags:
	make build && ldd packer ; file packer ; ./packer autoconf check

test-autoconf:
	rm packer packer-autoconf || true
	make build
	./packer autoconf setup -r age1f048u2u7kd7d3ywpzts03z9mzr02s3rcctw6vx9khlwct5x55q4slx4nfr -n Test1 -r age1dc2vud3kukzkqqsgfqth7qdaz57wlrq30ernzyzlweddgnas2qfsueskyw -n Test2
	chmod +x packer-af
	#tail -n 1 packer-af
	./packer-af autoconf check
