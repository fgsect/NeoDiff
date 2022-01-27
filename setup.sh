#!/bin/sh

echo "getting git submodules for EVMs"
git submodule init
git submodule update

echo "building go-ethereum (install go for this)"
make -C ./go-ethereum all

echo "building openethereum (install rust for this)"
cd ./openethereum/bin/evmbin
cargo build --release
cd ../../..

echo "Installing reqs for us, creating virtualenv"
virtualenv -p "$(command -v python3)" "$(pwd)/.env"
. .env/bin/activate
pip install -r requirements.txt

echo "Installing reqs for neopython"
cd neo-python
pip install -r requirements.txt
cd ..

echo "Done building :)"
echo "Activate the virtualenv with:"
echo ". .env/bin/activate"
