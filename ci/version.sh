#!/bin/bash

NEW_VERSION="$1"
TOML_CLI_REVISION="1a997d4"

if [ -z "$NEW_VERSION" ]; then
    exitWithErrMsg  "You have to specify new version, example: ./version 1.10.1"
fi

echo "Cloning toml-cli at revision $TOML_CLI_REVISION"
git clone https://github.com/Patrik-Stas/toml-cli.git /tmp/toml-cli &&
    cd /tmp/toml-cli &&
    git checkout "$TOML_CLI_REVISION" &&
    cd -

echo "Building toml-cli"
cargo build --manifest-path=/tmp/toml-cli/Cargo.toml

echo "Testing toml-cli"
/tmp/toml-cli/target/debug/toml --help

TOML_PATH_ARIES_VCX_DIR="$(dirname "$0")/../libvcx"
TOML_PATH_ARIES_VCX_TOML="$TOML_PATH_ARIES_VCX_DIR/Cargo.toml"
echo "TOML_PATH_ARIES_VCX_DIR=$TOML_PATH_ARIES_VCX_DIR"
echo "TOML_PATH_ARIES_VCX_TOML=$TOML_PATH_ARIES_VCX_TOML"

TOML_PATH_AGENCY_DIR="$(dirname "$0")/../agency_client"
TOML_PATH_AGENCY_TOML="$TOML_PATH_AGENCY_DIR/Cargo.toml"

echo "Bumping versions"
/tmp/toml-cli/target/debug/toml set "$TOML_PATH_ARIES_VCX_TOML" package.version "$NEW_VERSION" > /tmp/Cargo1.toml
/tmp/toml-cli/target/debug/toml set "$TOML_PATH_ARIES_VCX_TOML" dependencies.agency_client.version "$NEW_VERSION" > /tmp/Cargo1.toml
cat /tmp/Cargo1.toml > "$TOML_PATH_ARIES_VCX_TOML"

echo "Aries VCX Toml version:"
/tmp/toml-cli/target/debug/toml get "$TOML_PATH_ARIES_VCX_TOML" package.version

/tmp/toml-cli/target/debug/toml set "$TOML_PATH_AGENCY_TOML" package.version "$NEW_VERSION" > /tmp/Cargo2.toml
cat /tmp/Cargo2.toml > "$TOML_PATH_AGENCY_TOML"

echo "Agency Client Toml version:"
/tmp/toml-cli/target/debug/toml get "$TOML_PATH_AGENCY_TOML" package.version