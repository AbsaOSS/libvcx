#!/bin/bash

TOML_PATH_ARIES_VCX_DIR="$(dirname "$0")/../libvcx"
TOML_PATH_ARIES_VCX_TOML="$TOML_PATH_ARIES_VCX_DIR/Cargo.toml"

TOML_PATH_AGENCY_DIR="$(dirname "$0")/../agency_client"
TOML_PATH_AGENCY_TOML="$TOML_PATH_AGENCY_DIR/Cargo.toml"

cd "$TOML_PATH_AGENCY_DIR" && cargo publish --allow-dirty --dry-run && cd -
cd "$TOML_PATH_ARIES_VCX_DIR" && cargo publish --allow-dirty --dry-run