# Detection Tool
This is a simple LKM rootkit detection tool for Linux 4.4+ on x86-64.

For more detailed explanations, please visit the [wiki](https://github.com/lckjosh/DetectionTool/wiki).

# Features
- Detect Hidden PIDs
- Detect Hidden Files
- Detect Hidden Network Ports
- Detect Hooked Functions
- Detect Hidden Modules

# Installation

## Dependencies
- Linux Headers 
- GCC Compiler (Version > 5.0.0)
- The Sleuth Kit (TSK) 
- Python 3
- pytsk3 library

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
```
# Usage  
__NOTE: RUN `sudo ./client -f` upon initial insertion of module to form initial baseline for detecting hidden inodes.__
```
sudo insmod detectiontool.ko
./client [option]

Options:
[-p] detect hidden PIDs (run with sudo)
[-f partition-to-scan ] detect hidden files (run with sudo)
[-n] detect hidden network ports (run with sudo)
[-s] detect hooked functions
[-m] detect hidden modules

Examples:
./client -p
./client -f /dev/sda1 
./client -n
./client -s
./client -m 
```
