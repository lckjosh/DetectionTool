#!/usr/bin/env python

import os
import sys
import time
import resource
import subprocess
from datetime import datetime
from pathlib import Path

# Check if pytsk3 module is installed as it is required by the script
try:
    import pytsk3
except ImportError:
    sys.exit(
        "Error: Python pytsk3 module is not installed. Install pytsk3 with [pip3 install pytsk3]")

# record estimated time for the script to be executed
start_time = time.time()

# for my usage to check the output
TEST_PRINT = 0

# files & dirs created by script
BASE_SCAN_FILE = "base-scan.txt"
FALSE_POSITIVE_FILE = "false-positives.txt"
CURRENT_SCAN_SET_FILE_PREFIX = "scan-set"
# files created by this script will be stored in this dir
NESTED_DIR_NAME = "HID-result"
# Use the following line instead for this python script to be executed from whichever directory the script is exectued, otherwise the script needs to be executed in the same directory as itself
# NESTED_DIR_PWD = os.path.dirname(os.path.realpath(__file__)) + "/" + NESTED_DIR_NAME + "/"
NESTED_DIR_PWD = NESTED_DIR_NAME + "/"

# creates nested directory for ./NESTED_DIR_NAME
Path(NESTED_DIR_PWD).mkdir(parents=True, exist_ok=True)

# variables for debugging
counter_dir = 0
counter_inode = 0

# ==== Functions ====

# Part 3 tsk_get_inode
# gets information from directory entry (inode of entry and see if the entry is another directory)


def tsk_get_inode(dirent):
    inode = None
    is_dir = False  # ask if is it another nested directory?
    if dirent.info.meta:  # im guessing this is metadata of dir ent
        # ignore these file entries
        if dirent.info.name.name.decode("ISO-8859-1") in ['.', '..']:
            pass
        elif dirent.info.name.type == pytsk3.TSK_FS_NAME_TYPE_REG and \
                dirent.info.meta.type == pytsk3.TSK_FS_META_TYPE_REG:
            # if the inode entry is a regular file, save inode number
            inode = int(dirent.info.meta.addr)
        elif dirent.info.name.type == pytsk3.TSK_FS_NAME_TYPE_DIR and \
                dirent.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR and \
                not dirent.info.name.name == '$OrphanFiles':
            # if the inode entry is a directory
            inode = int(dirent.info.meta.addr)
            is_dir = True
    return (inode, is_dir)

# Part 2 tsk_walk_path
# inodes is basically a set of inode(s).


def tsk_walk_path(fs, inode, inodes=set(), inodes_dir=set(), counter=[0]):
    global counter_dir  # number of directories find inodes
    counter_dir += 1
    if isinstance(inode, str):
        cur = fs.open_dir(inode)  # opens directory name (e.g /)
    else:
        # when subdir is entered into, inode number is used instead of location
        cur = fs.open_dir(inode=inode)
    while True:
        try:
            dirent = cur.__next__()
            # gets information from directory entry (inode of entry and see if the entry is another directory)
            inode, is_dir = tsk_get_inode(dirent)
            if isinstance(inode, int):
                # add inode of dirent to a list counter_dir inodes
                inodes.add(inode)
                if is_dir:
                    # later return a list of inodes of directories.
                    inodes_dir.add(inode)
        except StopIteration:
            break
    return inodes, inodes_dir


# Part 1 get_tsk_inodes
def get_tsk_inodes(volume, root):
    try:
        # open the extX file system (e.g. /dev/sda1)
        img = pytsk3.Img_Info(volume)
        # FS_Info used as a handle for more detailed file system analysis. Check if file system of volume is of extX
        try:
            fs = pytsk3.FS_Info(img)
        except OSError as e:
            print(e)
            sys.exit("Error: file system of " + volume +
                     " is not supported by hidden-inode-detector.py. Only ext2/ext3/ext4 file systems are supported.")

        # goes to tsk_walk_path(). root is /
        # first time scan to collect inodes in same (root) dir
        my_inodes, my_inodes_dir = tsk_walk_path(fs=fs, inode=root)
    except (OSError) as e:
        print(e)
        sys.exit("Error: " + volume + " is not a valid mount point")
    # This part tries to go through each dir found the first tsk_walk_path scan, and so on.
    seen = my_inodes_dir.copy()
    active = my_inodes_dir.copy()
    while active:
        next_active = set()
        for current_inode_dir in active:
            test = tsk_walk_path(fs=fs, inode=current_inode_dir)
            for result in test[1]:
                if result not in seen:
                    seen.add(result)
                    next_active.add(result)
        active = next_active

    return my_inodes


def get_fs_inodes(path):
    inodes = set()
    # get status of file descriptor. stat() syscall
    path_dev = os.stat(path).st_dev  # dev = device
    # extract major and minor number of device
    major, minor = os.major(path_dev), os.minor(path_dev)
    for d in os.walk(path):  # os.walk() generate file names in a directory tree
        st = os.stat(d[0]).st_dev
        # Only search the same device as that of 'path'
        if (major, minor) != (os.major(st), os.minor(st)):
            continue

        for f in d[2]:
            abs_f = '%s/%s' % (d[0], f)
            try:
                inodes.add(os.stat(abs_f).st_ino)
            except OSError:
                # Ignore dangling symlinks
                if not os.path.islink(abs_f):
                    raise
        if path != d[0]:
            inodes.add(os.stat(d[0]).st_ino)
    return inodes


def create_file_title(title):
    # returns the file title with a timestamp and an index.
    now = datetime.now()
    index = 1
    stamped_title = str(title) + "-" + str(now.date()) + \
        "-" + str(index) + ".txt"
    while os.path.exists(NESTED_DIR_PWD + stamped_title):
        index += 1
        stamped_title = title + str(now.date()) + "-" + str(index) + ".txt"
    return stamped_title


def exception_error(error_message):
    # returns error message AND removes file created so far by current scan.
    print("Error: " + error_message)
    if os.path.isfile(current_scan):
        os.remove(current_scan)
    sys.exit("Error: Current scan is terminated.")

# ==== Start =====


# root check
if not os.geteuid() == 0:
    sys.exit("Error: This script must be run as root!")

l = len(sys.argv)
if l > 1:
    volume = sys.argv[1]  # /dev/sda1
if l > 2:
    mount_path = sys.argv[2]  # /mnt or /
if l > 3:
    root = sys.argv[3]  # /<directory-to-check>
else:
    root = '/'
if l > 4:
    # if additional_option is 'hideinodepwd', hide inode pathway dir in output
    additional_option = sys.argv[4]
else:
    additional_option = ""

# os.system executes the command in a subshell
os.system('/bin/sync')
# this command free pagecache, frees up kernel memory
os.system('/bin/echo 3 > /proc/sys/vm/drop_caches')

if os.path.exists(NESTED_DIR_PWD + BASE_SCAN_FILE):
    print("[*] === Started Hidden Files & Directories scan to search for inodes that may be hidden by a possible rootkit ===")
else:
    print("[*] Creating baseline for root directory on " + volume + " ...")

# the main two tests (Takes around a minute)
print("[*] Evaluating disk view of file system via read() syscall... [get_tsk_inode test]")
tsk_inodes = get_tsk_inodes(volume=volume, root=root)  # via read() syscall
print("[*] Evaluation of disk view of file system done")
print("[*] Evaluating user view of mounted file system via stat(), getdent(), etc... [get_fs_inodes test]")
fs_inodes = get_fs_inodes(mount_path)  # via getdents() and stat() syscall
print("[*] Evaluation of user view of mounted file system done")

# current_set stores result of current scan (may contain many false positives)
# current_set is compared with base_set for anomalies for concurrent scans.
# elements included in tsk_inodes but not fs_inodes
current_set = tsk_inodes - fs_inodes

if (TEST_PRINT):
    print("number of inodes from tsk_inodes: " + str(len(tsk_inodes)))
    print("number of dir from tsk_inodes: " + str(counter_dir))
    print("length of current_set: " + str(len(current_set)))

# anomalies_set is used to store the differnce of current_set between the base scan and the current scan.
# The first base scan contains false positives, so we have to compare a second scan to the base scan to find anamolies between the scans.
anomalies_set = set()

# first base scan, write current_set set of inodes in BASE_SCAN_FILE into basescan.txt line by line
if not os.path.exists(NESTED_DIR_PWD + BASE_SCAN_FILE):
    print()
    base_record = open(NESTED_DIR_PWD + BASE_SCAN_FILE, 'x')
    for i in current_set:
        base_record.write(str(i))
        base_record.write("\n")
    base_record.close()

    if not os.path.exists(NESTED_DIR_PWD + FALSE_POSITIVE_FILE):
        # creates false-positive.txt for subsequent use
        open(NESTED_DIR_PWD + FALSE_POSITIVE_FILE, 'a').close()

    print("\u001b[1m\u001b[32m[OK] Baseline successfully set \u001b[0m")
    print()
    print("[*] Baseline set is stored in (HID_result/base-scan.txt). Do not modify the contents of the base-scan.txt file.")
    print("[*] You can optionally rename subsequent hidden files & directory scans (scan-*.txt) to base-scan.txt to replace baseline.")
    print("[*] You can optionally include entries written to false-positives.txt, which will be ignored by the scan.")
    print("[*] Subsequent scans will be compared with this baseline.")
    print()
    print("[*] Baseline Scan finished in %s seconds" %
          "{:.2f}".format((time.time() - start_time)))
    # print("===== Hidden Files & Directory Baseline Scan Finished ======")
else:
    # subsequent scans (if the base scan is already done beforehand)
    # timestamp the prefix. scan file is not used in comparison currently, just to log.
    current_scan = create_file_title(CURRENT_SCAN_SET_FILE_PREFIX)
    current_record = open(NESTED_DIR_PWD + current_scan, 'x')
    for i in current_set:
        current_record.write(str(i))
        current_record.write("\n")

    print("[*] Current hidden files & directory scan set file is saved to: " +
          str(NESTED_DIR_PWD + current_scan))
    current_record.close()

    # create a set from the results from the base scan, of which the element of inodes are stored in basescan.txt
    base_record = open(NESTED_DIR_PWD + BASE_SCAN_FILE, 'r')
    base_set = set()
    line = base_record.readline()
    while line:
        # fills up base_set from base-scan.txt, removes trailing \n at each line and cast to integer
        base_set.add(int(line.split('\n')[0]))
        line = base_record.readline()
    base_record.close()

    # sanity check
    if (TEST_PRINT):
        # should return true, sometimes false if some base_set inodes have modified or recently deleted.
        print("base_set is a subset of current_set: " +
              str(base_set.issubset(current_set)))
        # should return false otherwise something is really wrong
        print("current_set is a subset of base_set: " +
              str(current_set.issubset(base_set)))

    # find new elements in current_set not in base_set, which supposedly is the inodes hidden by a potential rootkit.
    anomalies_set = current_set.difference(base_set)

    if (TEST_PRINT):
        print("length of extracted base_set from base-scan.txt: " +
              str(len(base_set)))  # from currentscan.txt
        print("length of anomalies_set: " + str(len(anomalies_set)))

    # print contents of anomalies_set if there are hidden files
    final_hidden_inodes = 0  # final_hidden_inodes counts the number of actual hits on the anomalies_set as some entries might be recently deleted with a '*' entry
    if anomalies_set:
        # print("contents of anomalies_set (possible hidden files): " + str(anomalies_set))
        print()
        if (additional_option != "hideinodepwd"):
            print("[*] Searching through list of possible hidden inodes... ")
        print()

        # Opens and reads the false-positive.txt file (into a false_positive_set) for entries which will be ignored.
        # Checks if file is empty. If empty, skip.
        false_positive_file_size = os.path.getsize(
            NESTED_DIR_PWD + FALSE_POSITIVE_FILE)
        if false_positive_file_size > 0:
            false_positive_record = open(
                NESTED_DIR_PWD + FALSE_POSITIVE_FILE, 'r')
            false_positive_set = set()
            false_positive_entry = false_positive_record.readline()
            while false_positive_entry:
                false_positive_set.add(false_positive_entry.split('\n')[0])
                false_positive_entry = false_positive_record.readline()
            if (TEST_PRINT):
                print("length of false_positive_set: " +
                      str(len(false_positive_set)))
                print("contents of false_positive set: " +
                      str(false_positive_set))

        for anomaly in anomalies_set:
            # print out pwd of possible hidden files by using tsk's ffind command
            # ffind -u /dev/sda1 <inode-value>
            try:
                process = subprocess.Popen(
                    ['ffind', '-u', str(sys.argv[1]), str(anomaly)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except FileNotFoundError:
                exception_error(
                    "Error: The Seluth Kit (TSK) is not installed. Install TSK with [sudo apt install seluthkit | sudo dnf install seluthkit].")
            stdout, stderr = process.communicate()
            ffind_output = stdout.decode("utf-8").split('\n')[0]
            if (ffind_output == "File name not found for inode"):
                continue  # ignore recently deleted entries that begins with with '*'
            else:
                if ((false_positive_file_size != 0) and (ffind_output in false_positive_set)):
                    # ignore entry if inode pwd matches any entry in false-positive.txt
                    continue
                else:
                    final_hidden_inodes += 1
                    os_cmd_output = ffind_output + "  (" + str(anomaly) + ")"
                    if (additional_option == "hideinodepwd"):
                        # if "hideinodepwd" argument is entered, which hides the output of the hidden inode pwd and number.
                        continue
                    elif (additional_option == ""):
                        print(
                            "\u001b[1m\u001b[31m[WARNING] Found hidden inode:  " + os_cmd_output + "\u001b[0m")

    if final_hidden_inodes:
        print()
        print("\u001b[1m\u001b[31m[WARNING] Hidden Files & Directory Scan complete. There may be possible rootkit(s) installed on the system that are currently hiding " +
              str(final_hidden_inodes) + " inode(s) [i.e. hidden files & directories].\u001b[0m")
        print()
    else:
        # no inodes in anomalies_set
        print()
        print(
            "\u001b[1m\u001b[32m[OK] No hidden inodes found in list of possible hidden inodes. \u001b[0m")
        print()
        print(
            "\u001b[1m\u001b[32m[OK] No anomalies detected. No rootkit(s) are actively hiding inodes. \u001b[0m")
        print()

    print("[*] === Hidden Files & Directory Scan finished in %s seconds ===" %
          "{:.2f}".format((time.time() - start_time)))
    print()
    # print("===== Hidden inode(s) Scan Finished =====")
