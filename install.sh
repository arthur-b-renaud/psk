#!/bin/sh
# PSK — Prompt Secret Killer installer
# Usage: curl -fsSL https://psk.dev/install.sh | sh
set -eu

REPO="psk-ai/psk"
BINARY="psk"
INSTALL_DIR="${PSK_INSTALL_DIR:-$HOME/.local/bin}"

main() {
    detect_platform
    fetch_latest_version
    download_and_install
    verify_installation
    echo ""
    echo "  PSK installed successfully!"
    echo "  Version: $VERSION"
    echo "  Binary:  $INSTALL_DIR/$BINARY"
    echo ""
    echo "  Get started:"
    echo "    psk install     # auto-detect and configure your AI agents"
    echo "    psk start       # start the proxy"
    echo "    psk gain        # check stats"
    echo ""
    check_path
}

detect_platform() {
    OS="$(uname -s)"
    ARCH="$(uname -m)"

    case "$OS" in
        Linux)  OS="linux" ;;
        Darwin) OS="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) OS="windows" ;;
        *) echo "Error: Unsupported OS: $OS" >&2; exit 1 ;;
    esac

    case "$ARCH" in
        x86_64|amd64)  ARCH="x86_64" ;;
        aarch64|arm64) ARCH="aarch64" ;;
        *) echo "Error: Unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    if [ "$OS" = "linux" ]; then
        TARGET="${ARCH}-unknown-linux-musl"
    elif [ "$OS" = "darwin" ]; then
        TARGET="${ARCH}-apple-darwin"
    elif [ "$OS" = "windows" ]; then
        TARGET="${ARCH}-pc-windows-msvc"
    fi

    echo "  Platform: ${OS}/${ARCH} (${TARGET})"
}

fetch_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"v\?\([^"]*\)".*/\1/')
    elif command -v wget >/dev/null 2>&1; then
        VERSION=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | head -1 | sed 's/.*"v\?\([^"]*\)".*/\1/')
    else
        echo "Error: curl or wget required" >&2
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        echo "Error: Could not determine latest version" >&2
        exit 1
    fi

    echo "  Version:  v${VERSION}"
}

download_and_install() {
    EXT="tar.gz"
    if [ "$OS" = "windows" ]; then
        EXT="zip"
    fi

    URL="https://github.com/${REPO}/releases/download/v${VERSION}/psk-${TARGET}.${EXT}"
    TMPDIR=$(mktemp -d)
    ARCHIVE="${TMPDIR}/psk.${EXT}"

    echo "  Downloading from ${URL}..."

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$URL" -o "$ARCHIVE"
    else
        wget -q "$URL" -O "$ARCHIVE"
    fi

    # Extract
    mkdir -p "$INSTALL_DIR"
    if [ "$EXT" = "tar.gz" ]; then
        tar -xzf "$ARCHIVE" -C "$TMPDIR"
    else
        unzip -q "$ARCHIVE" -d "$TMPDIR"
    fi

    # Find and install the binary
    if [ -f "${TMPDIR}/${BINARY}" ]; then
        mv "${TMPDIR}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    elif [ -f "${TMPDIR}/psk-${TARGET}/${BINARY}" ]; then
        mv "${TMPDIR}/psk-${TARGET}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
    else
        # Search for it
        FOUND=$(find "$TMPDIR" -name "$BINARY" -type f | head -1)
        if [ -n "$FOUND" ]; then
            mv "$FOUND" "${INSTALL_DIR}/${BINARY}"
        else
            echo "Error: Could not find binary in archive" >&2
            rm -rf "$TMPDIR"
            exit 1
        fi
    fi

    chmod +x "${INSTALL_DIR}/${BINARY}"
    rm -rf "$TMPDIR"
}

verify_installation() {
    if [ -x "${INSTALL_DIR}/${BINARY}" ]; then
        echo "  Installed: $("${INSTALL_DIR}/${BINARY}" version 2>/dev/null || echo 'psk (version check failed)')"
    else
        echo "Error: Installation failed" >&2
        exit 1
    fi
}

check_path() {
    case ":$PATH:" in
        *":${INSTALL_DIR}:"*) ;;
        *)
            echo "  NOTE: ${INSTALL_DIR} is not in your PATH."
            echo "  Add it with:"
            echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
            echo ""
            ;;
    esac
}

main "$@"
