#!/bin/env python3

import hashlib, subprocess, os, argparse, tarfile, zipfile, tempfile, shutil
import wget

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--version", type=str)
parser.add_argument("-d", "--directory", type=str)
parser.add_argument("-os", "--OperatingSystem", type=str)

args = parser.parse_args()
version = args.version
directory = args.directory
operating_system = args.OperatingSystem
md5 = None
patch = []
patch.append('cd /d "C:\Program Files\Sublime Text" || exit')
patch.append('copy /y sublime_text.exe sublime_text.exe.bak || exit')
# print(patch)

def make_bytes_literal(hex_val):
    for item in hex_val:
        if isinstance(item, str):
            item = hex_val[item]
        item["value"] = bytes.fromhex(item["value"].replace(" ", "    "))
        item["size"] = len(item["value"])
    return hex_val

def get_offset(bin_file, data):
    offsets = []
    byte, size, off = data["value"], data["size"], data["offset"]
    i = 0
    flag = False

    with open(bin_file, "rb") as input_file:
        while True:
            b = input_file.read(1)
            if not b:
                break

            if b == int.to_bytes(byte[i]):
                i += 1
                if i == size:
                    offset = hex(input_file.tell() - size + off)
                    print(f" => {data['name']}: {offset}")
                    flag = True
                    offsets.append(offset)
                    # reset
                    i = 0
            else:
                i = 0
                
    if not flag:
        return False, None
    return True, offsets


def get_version(bin_file):
    return subprocess.Popen(f"{bin_file} -v".split(), stdout=subprocess.PIPE).communicate()[0].decode("utf-8")

def print_version(bin_file):
    vvv = " | " + get_version(bin_file).strip() + " |"

    print("")
    print("", "-" * (len(vvv) - 1))
    print(vvv)
    print("", "-" * (len(vvv) - 1))
    print("")

def get_md5(bin_file):
    with open(bin_file, "rb") as input_file:
        f = input_file.read()
        md5 = hashlib.md5(f).hexdigest()
        print(f" => MD5 Checksum -> {md5}")
        print(f" => SHA1 Checksum -> {hashlib.sha1(f).hexdigest()}")
        # print(f" => SHA256 Checksum -> {hashlib.sha256(file).hexdigest()}")
        print("")
    input_file.close()
    patch.append(f'certutil -hashfile sublime_text.exe md5 | find /i "{md5}" || exit')


def get_hex():
    hex_val = backup = []
    if operating_system == "linux" or operating_system == "lin":
        hex_val = [
            {
                "id": "1",
                "name": "Initial License Check",
                "value": "AF 31 C0 C3 55 41 57 41 56 41 55",
                "offset": 4,
                "patch": "AC 31 C0 C3 55 41 57 41 56 41 55",
                "status": "ok",
            },
            {
                "id": "2",
                "name": "Persistent License Check 1",
                "value": "BA 88 13 00 00 E8",
                "offset": 5,
                "patch": "BA 88 13 00 00 E8",
                "status": "ok",
            },
            {
                "id": "3",
                "name": "Persistent License Check 2",
                "value": "BA 98 3A 00 00 E8",
                "offset": 5,
                "patch": "BA 98 3A 00 00 E8",
                "status": "ok",
            },
            {
                "id": "4",
                "name": "Disable Server Validation Thread",
                "value": "4D 00 48 89 C5 48 89 DF E8",
                "offset": -59,
                "patch": "4D 00 48 89 C5 48 89 DF E8",
                "status": "not ok",
            },
            {
                "id": "5",
                "name": "Disable License Notify Thread",
                "value": "83 AC 03 00",
                "offset": 3,
                "patch": "83 AC 03 00",
                "status": "not ok",
            },
            {
                "id": "6",
                "name": "Disable Crash Reporter",
                "value": "D2 C3 CC CC 55",
                "offset": 4,
                "patch": "D2 C3 CC CC 55",
                "status": "ok",
            },
        ]
        backup = {
            "1": {
                    "id": "11",
                    "name": "Initial License Check",
                    "value": "AC 31 C0 C3 55 41 57 41 56 41 55",
                    "offset": 4,
                    "patch": "AC 31 C0 C3 55 41 57 41 56 41 55",
                    "status": "ok",
                },
        }
    elif operating_system == "windows" or operating_system == "win":
        hex_val = [
                {
                    "id": "1",
                    "name": "Initial License Check",
                    "value": "6C 69 63 65 6E 73 65 2E 73 75 62 6C 69 6D 65 68 71 2E 63 6F 6D",
                    "offset": 0,
                    "patch": "73 75 62 6C 69 6D 65 68 71 2E 6C 6F 63 61 6C 68 6F 73 74 00 00",
                    "status": "ok",
                },
                {
                    "id": "2",
                    "name": "Persistent License Check",
                    "value": "28 5B 5F 5E 41 5E C3 41 57 41 56 56 57 55 53 B8",
                    "offset": 0,
                    "patch": "28 5B 5F 5E 41 5E C3 33 C0 FE C0 C3 57 55 53 B8",
                    "status": "ok",
                }
            ]
    else:
        print(" => Unsupported OS!")
        print(" => Supported OS: linux, windows")
        exit(1)

    return hex_val, backup

def common(bin_file):
    hex_val, backup = get_hex()

    print_version(bin_file)
    get_md5(bin_file)
    
    hex_val = make_bytes_literal(hex_val)
    backup = make_bytes_literal(backup)
    for index, item in enumerate(hex_val):

        # DEBUG
        # if item["status"] != "ok":
        #     continue
        status, offsets = get_offset(bin_file, item)
        if not status:
            bak = backup.get(item["id"], None)
            if bak is not None:
                # print(" => Trying Alternative Pattern...")
                hex_val.insert(index + 1, backup[item["id"]])
            else:
                print(f" => {item['name']}: Not found")
                # print(" => No Alternative Pattern Found")
                # break
        else:
            if len(offsets) == 1:
                patch.append(f"echo {offsets[0]}: {item['patch']} | xxd -r - sublime_text.exe")
    print("")

def custom_bar(current, total, width=50):
    return wget.bar_adaptive(round(current/1024/1024, 2), round(total/1024/1024, 2), width) + ' MB'

def download(url, path):
    print(" => Downloading...")
    wget.download(url=url, out=path, bar=custom_bar)
    print("")

def extract(path, ext):
    dest = path.replace(ext, "")

    if ext == ".tar.xz":
        file = tarfile.open(path)
        file.extractall(dest)
        file.close()
    elif ext == ".zip":
        with zipfile.ZipFile(path,"r") as zip_ref:
            zip_ref.extractall(dest)
        zip_ref.close()
    else:
        print(" => Unsupported File Type!")
        print(" => Supported File Types: tar.xz, zip")
        exit(1)

def delete(path):
    os.chmod(path, 0o777)
    try:
        os.remove(path)
    except:
        shutil.rmtree(path)

def get_file_names(dir, ext):
    arr = operating_system.listdir(dir)
    return [f"{dir}/{item}" for item in arr if item.endswith(ext)]

def run_find(file_url, ext):
    dir_url = file_url.replace(ext, "")
    extract(file_url, ext)
    if operating_system == "linux" or operating_system == "lin":
        bin_file = f"{dir_url}/sublime_text"
    else:   # For other file type the script will exit long before this function
        bin_file = f"{dir_url}\\sublime_text.exe"

    common(bin_file)
    delete(dir_url)

def make_patch():
    if operating_system == "linux" or operating_system == "lin":
        p = "patch.sh"
    else:
        p = "patch.bat"
    f = open(p, "w")
    for item in patch:
        f.writelines(item + "\n")
    f.close()


def main():
    if not directory:
        if not version:
            print(" => Directory or Version is required")
            return

        if operating_system == "linux" or operating_system == "lin":
            ext = ".tar.xz"
            base_url = f"https://download.sublimetext.com/sublime_text_build_{version}_x64.tar.xz"
            file_url = f"/tmp/sublime_text_build_{version}_x64.tar.xz"
        else:
            ext = ".zip"
            wintmp = tempfile.gettempdir()
            base_url = f"https://download.sublimetext.com/sublime_text_build_{version}_x64.zip"
            file_url = f"{wintmp}\\sublime_text_build_{version}_x64.zip"
        download(base_url, file_url)
        run_find(file_url, ext)
        delete(file_url)
        make_patch()
    else:
        files = get_file_names(directory, ".tar.xz")
        for file_url in files:
            run_find(file_url, ".tar.xz")


if __name__ == "__main__":
    main()
