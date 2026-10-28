# 便携构建：产物是单文件，内嵌 payload + 71 份 profile，
# 拷到别的机器后，同目录放一个 KSU 管理器 APK 即可直接运行。
.PHONY: all build test vet fmt arm64 win mac install dist clean

GO ?= go
BIN ?= bin/ghostlock
export GOFLAGS := -mod=mod

all: build

build:
	$(GO) build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/ghostlock

arm64:
	GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o bin/ghostlock-linux-arm64 ./cmd/ghostlock

win:
	GOOS=windows GOARCH=amd64 $(GO) build -trimpath -ldflags "-s -w" -o bin/ghostlock.exe ./cmd/ghostlock

mac:
	GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags "-s -w" -o bin/ghostlock-macos-arm64 ./cmd/ghostlock

# 打一个可以直接分发的目录：二进制 + 说明
dist: build
	rm -rf dist && mkdir -p dist
	cp $(BIN) dist/
	cp README.md dist/README.md
	@echo "把 KSU 管理器 APK 放进 dist/，然后 cd dist && ./ghostlock"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w cmd internal

install: build
	install -Dm755 $(BIN) $(HOME)/.local/bin/ghostlock

clean:
	rm -rf bin dist
