#!/bin/bash

cd /

apt install python3.10-venv

python3 -m venv amigo-env

source amigo-env/bin/activate

pip3 install -r /protest/py-requirements.txt