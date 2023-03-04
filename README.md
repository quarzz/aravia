## Setup (Linux with apt)

```console
sudo apt update
sudo apt install build-essential libssl-dev libboost-all-dev cmake
```
## Build

```console
mkdir build
cd build
cmake ..
make
```

## Run
Run with BINANCE_API_KEY and BINANCE_SECRET_KEY env variables set.

```
./aravia SYMBOL QUANTITY STOP_LOSS STOP_GAIN HOLD_TIMEOUT COOLDOWN_TIME
```

For example
```
./aravia BTC/USDT 0.001 0.05 0.05 15 10
```
