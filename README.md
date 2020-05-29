# Internship Project
Master branch should only contain fully working code. Create feature branch to work on new features and create a pull request when code is ready to be merged into master.

# Detection Tool
This is a simple rootkit detection tool for Linux that has been tested on Ubuntu 16.04 (4.15.0-45-generic). 

# Features
- Detect Hidden PIDs
- Detect Hidden Files
- Detect Hooked System Call Table

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
[-s] detect hooked system calls
```
