# Detection Tool
This is a simple LKM rootkit detection tool for Linux that has been tested on Ubuntu 16.04 (4.15.0-45-generic).  

For more detailed explanations, please visit the [wiki](https://github.com/lckjosh/DetectionTool/wiki).

# Features
- Detect Hidden PIDs
- Detect Hidden Files
- Detect Hooked Functions
- Detect Hidden Modules

# Installation

## Dependencies
- Linux Headers 
- GCC Compiler (Version > 5.0.0)
- The Sleuth Kit (TSK) 
- Python (Version 3.5)
- pytsk3 module

For Debian-based distros: 
```
sudo apt install linux-headers-$(uname -r) build-essential sleuthkit python3 python3-pip
pip3 install pytsk3
```
## Cloning and Compilation
```
git clone https://github.com/lckjosh/DetectionTool.git
cd DetectionTool
make
gcc client.c $(python3.5-config --cflags) $(python3.5-config --ldflags) -o client
```

# Usage
```
sudo insmod detectiontool.ko
./client [option]

Options:
[-p] detect hidden PIDs
[-f] detect hidden files
[-s] detect hooked functions
[-m] detect hidden modules
```
