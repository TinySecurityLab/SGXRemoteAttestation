#！/usr/bin/bash

source /home/u/Desktop/sgx/sgxsdk/environment

cd client
make clean
make SGX_MODE=SIM

cd ..
cd server
make clean
make SGX_MODE=SIM

cd ..