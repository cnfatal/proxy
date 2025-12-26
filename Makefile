# Transparent Proxy Makefile

BINARY_NAME := tproxy
BUILD_DIR := build
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /etc/tproxy
SYSTEMD_DIR := /etc/systemd/system

# Go build flags
LDFLAGS := -s -w
GOFLAGS := -trimpath

.PHONY: all build clean install uninstall systemd-install systemd-uninstall help

# Default target
all: build

# Build the binary (static build)
build:
	@echo "Building $(BINARY_NAME) (static)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .
	@echo "Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@echo "Clean complete"

# Install binary and config
install:
	@echo "Installing $(BINARY_NAME)..."
	@install -d $(INSTALL_DIR)
	@install -m 755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	@install -d $(CONFIG_DIR)
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		install -m 644 config.example.yaml $(CONFIG_DIR)/config.yaml; \
		echo "Installed default config to $(CONFIG_DIR)/config.yaml"; \
	else \
		echo "Config file already exists, skipping"; \
	fi
	@echo "Install complete"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit config: sudo vim $(CONFIG_DIR)/config.yaml"
	@echo "  2. Install systemd service: sudo make systemd-install"

# Uninstall binary and config
uninstall: systemd-uninstall
	@echo "Uninstalling $(BINARY_NAME)..."
	@rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstall complete"
	@echo "Note: Config directory $(CONFIG_DIR) was not removed"

# Install systemd service
systemd-install: install
	@echo "Installing systemd service..."
	@install -m 644 tproxy.service $(SYSTEMD_DIR)/tproxy.service
	@systemctl daemon-reload
	@echo "Systemd service installed"
	@echo ""
	@echo "To start the service:"
	@echo "  sudo systemctl start tproxy"
	@echo ""
	@echo "To enable on boot:"
	@echo "  sudo systemctl enable tproxy"
	@echo ""
	@echo "To check status:"
	@echo "  sudo systemctl status tproxy"

# Uninstall systemd service
systemd-uninstall:
	@echo "Uninstalling systemd service..."
	@-systemctl stop tproxy 2>/dev/null || true
	@-systemctl disable tproxy 2>/dev/null || true
	@rm -f $(SYSTEMD_DIR)/tproxy.service
	@systemctl daemon-reload
	@echo "Systemd service uninstalled"

# Run cleanup (remove nftables rules)
cleanup:
	@echo "Cleaning up nftables rules..."
	@$(INSTALL_DIR)/$(BINARY_NAME) -cleanup || $(BUILD_DIR)/$(BINARY_NAME) -cleanup
	@echo "Cleanup complete"

# Development: run locally
run: build
	@echo "Running $(BINARY_NAME) (requires root)..."
	sudo $(BUILD_DIR)/$(BINARY_NAME) -config config.example.yaml

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Run linter
lint:
	@echo "Running linter..."
	go vet ./...
	@echo "Lint complete"

# Show help
help:
	@echo "Available targets:"
	@echo "  build            - Build the binary"
	@echo "  clean            - Remove build artifacts"
	@echo "  install          - Install binary and config"
	@echo "  uninstall        - Remove binary (keeps config)"
	@echo "  systemd-install  - Install as systemd service"
	@echo "  systemd-uninstall- Remove systemd service"
	@echo "  cleanup          - Remove nftables rules"
	@echo "  run              - Build and run locally (dev)"
	@echo "  test             - Run tests"
	@echo "  lint             - Run linter"
	@echo "  help             - Show this help"
