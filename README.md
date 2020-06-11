# Detection Tool
This is a simple LKM rootkit detection tool for Linux that has been tested on Ubuntu 16.04 (4.15.0-45-generic).  
NOTE: Ensure SMAP is disabled (most rootkits will not work with it enabled anyway)

For more detailed explanations, please visit the [wiki](https://github.com/lckjosh/DetectionTool/wiki).

# Features
- Detect Hidden PIDs
- Detect Hidden Files
- Detect Hooked Functions
- Detect Hidden Modules

# Installation
```
git clone https://github.com/lckjosh/DetectionTool.git
cd DetectionTool
make
gcc client.c -o client
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
