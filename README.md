# Detection Tool
This is a simple rootkit detection tool for Linux that has been tested on Ubuntu 16.04 (4.15.0-45-generic). 

# Features
- Detect Hidden PIDs
- Detect Hidden Files
- Detect Hooked Functions

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
```
