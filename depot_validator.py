#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
## Multi-threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue # Thread-Safe variable writing.
##
from datetime import datetime
from fnmatch import fnmatch
from glob import glob
from hashlib import sha1
from io import BytesIO
from os import scandir, makedirs, remove
from os.path import dirname, exists
from pathlib import Path
from struct import unpack
from sys import argv
from zipfile import BadZipFile, ZipFile
import lzma
import csv

if __name__ == "__main__": # exit before we import our shit if the args are wrong
    parser = ArgumentParser(description='Verifies downloaded depots.')
    parser.add_argument('depotid', type=int)
    parser.add_argument('depotkey', type=str, nargs='?')
    parser.add_argument('-b', dest="backup", help="Path to a .csd backup file to review (the manifest must also be present in the depots folder)", nargs='?')
    parser.add_argument('-f', dest="files", help="List of files to review (space-separated)", nargs='+')
    parser.add_argument('-F', dest="file_list", help="Path to a text or CSV file containing the list of files to review", nargs='?')
    # parser.add_argument('-m', dest="manifests", help="Path to the manifest file to validate the files", nargs='?')
    parser.add_argument('-t', type=int, default=1, dest="threads", help="specifies the number of threads to use for processing the files")
    args = parser.parse_args()
    if args.backup and args.manifests:
        print("At this time, backup and manifest filtering can not be used together.")
        parser.print_help()
        exit(1)
        
    file_list = []
    if args.file_list:
        with open(args.file_list, 'r') as f:
            if args.file_list.endswith('.csv'):
                reader = csv.reader(f)
                for row in reader:
                    file_list.extend(row)
            else:
                file_list.extend(f.read().splitlines())

    if args.files:
        file_list.extend(args.files)

from steam.core.manifest import DepotManifest
from steam.core.crypto import symmetric_decrypt
from chunkstore import Chunkstore

def process_file(file, value, badfiles):
    if args.files and file not in args.files:
        return None, True  # Skip files not in the list
    
    try:
        if args.backup:
            chunkhex = hexlify(file).decode()
            chunk_data = None
            is_encrypted = False
            try:
                chunkstore = chunkstores[chunks_by_store[file]]
                chunk_data = chunkstore.get_chunk(file)
                is_encrypted = chunkstore.is_encrypted
            except Exception as e:
                print(f"\033[31mError retrieving chunk\033[0m {chunkhex}: {e}")
                ##breakpoint()
                badfiles.put(chunkhex)
                return chunkhex, False
            if is_encrypted:
                if args.depotkey:
                    decrypted = symmetric_decrypt(chunk_data, args.depotkey)
                else:
                    print("\033[31mERROR: chunk %s is encrypted, but no depot key was specified\033[0m" % chunkhex)
                    badfiles.put(chunkhex)
                    return chunkhex, False
            else:
                decrypted = chunk_data
        else:
            chunkhex = hexlify(unhexlify(file.replace("_decrypted", ""))).decode()
            if exists(path + chunkhex):
                with open(path + chunkhex, "rb") as chunkfile:
                    if args.depotkey:
                        try:
                            decrypted = symmetric_decrypt(chunkfile.read(), args.depotkey)
                        except ValueError as e:
                            print(f"{e}")
                            print(f"\033[31mError, unable to decrypt file:\033[0m {chunkhex}")
                            badfiles.put(chunkhex)
                            return chunkhex, False
                    else:
                        print("\033[31mERROR: chunk %s is encrypted, but no depot key was specified\033[0m" % chunkhex)
                        badfiles.put(chunkhex)
                        return chunkhex, False
            elif exists(path + chunkhex + "_decrypted"):
                with open(path + chunkhex + "_decrypted", "rb") as chunkfile:
                    decrypted = chunkfile.read()
            else:
                print("missing chunk " + chunkhex)
                badfiles.put(chunkhex)
                return chunkhex, False
        
        decompressed = None
        if decrypted[:2] == b'VZ': # LZMA
            decompressedSize = unpack('<i', decrypted[-6:-2])[0]
            print("Testing (LZMA) from chunk", chunkhex, "Size:", decompressedSize)
            try:
                decompressed = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[lzma._decode_filter_properties(lzma.FILTER_LZMA1, decrypted[7:12])]).decompress(decrypted[12:-10])[:decompressedSize]
            except lzma.LZMAError as e:
                print(f"\033[31mFailed to decompress:\033[0m {chunkhex}")
                print(f"\033[31mError:\033[0m {e}")
                badfiles.put(chunkhex)
                return chunkhex, False
        elif decrypted[:2] == b'PK': # Zip
            print("Testing (Zip) from chunk", chunkhex)
            try:
                zipfile = ZipFile(BytesIO(decrypted))
                decompressed = zipfile.read(zipfile.filelist[0])
            except BadZipFile:
                print(f"\033[31mFailed to decompress:\033[0m {chunkhex}")
                print(f"\033[31mError:\033[0m {BadZipFile}")
                badfiles.put(chunkhex)
                return chunkhex, False
            except Exception as e:
                print(f"\033[31mFailed to decompress:\033[0m {chunkhex}")
                badfiles.put(chunkhex)
                return chunkhex, False
        else:
            print("\033[31mERROR: unknown archive type\033[0m", decrypted[:2].decode())
            badfiles.put(chunkhex)
            return chunkhex, False
        sha = sha1(decompressed)
        if sha.digest() != unhexlify(chunkhex):
            print("\033[31mERROR: sha1 checksum mismatch\033[0m (expected %s, got %s)" % (chunkhex, sha.hexdigest()))
            badfiles.put(chunkhex)
            return chunkhex, False
    except IsADirectoryError:
        return file, False

if __name__ == "__main__":
    path = "./depots/%s/" % args.depotid
    keyfile = "./keys/%s.depotkey" % args.depotid
    if args.depotkey:
        args.depotkey = bytes.fromhex(args.depotkey)
    elif exists(keyfile):
        with open(keyfile, "rb") as f:
            args.depotkey = f.read()
    elif exists("./depot_keys.txt"):
        with open("./depot_keys.txt", "r", encoding="utf-8") as f:
            for line in f.read().split("\n"):
                line = line.split("\t")
                try:
                    if int(line[0]) == args.depotid:
                        args.depotkey = bytes.fromhex(line[2])
                        break
                except ValueError:
                    pass
            if not args.depotkey:
                print("\033[31mERROR: files are encrypted, but no depot key was specified and no key for this depot exists in depot_keys.txt\033[0m")
                exit(1)
    else:
        print("\033[31mERROR: files are encrypted, but no depot key was specified and no depot_keys.txt or depotkey file exists\033[0m")
        exit(1)

    chunks = {}
    if args.backup:
        chunkstores = {}
        chunks_by_store = {}
        for csm in glob(args.backup.replace("_1.csm","").replace("_1.csd","") + "_*.csm"):
            chunkstore = Chunkstore(csm)
            chunkstore.unpack()
            for chunk, _ in chunkstore.chunks.items():
                chunks[chunk] = _
                chunks_by_store[chunk] = csm
            chunkstores[csm] = chunkstore
    # elif args.manifests:
    #     manifestChunks = set()
    #     manifestFiles = []
    #     if len(args.manifests) == 1 and Path(args.manifests[0]).is_dir():
    #         manifestFiles = [Path(args.manifests[0]) / data.name for data in scandir(args.manifests[0]) if data.is_file() and data.name.endswith(".zip")]
    #     else:
    #         manifestFiles = args.manifests

    #     for eachManifest in manifestFiles:
    #         with open(eachManifest, "rb") as f:
    #             manifest_data = f.read()
    #             manifest = DepotManifest.deserialize(manifest_data)
    #             if manifest.filenames_encrypted:
    #                 manifest.decrypt_filenames(args.depotkey)
    #             for files in manifest.iter_files():
    #                 for chunk in sorted(files.chunks, key=lambda chunk: chunk.offset):
    #                     manifestChunks.add(chunk.sha)
    #     for name in manifestChunks:
    #         chunks[name] = 0
    else:
        chunkFiles = [data.name for data in scandir(path) if data.is_file()
        and not data.name.endswith(".zip")]
        for name in chunkFiles: chunks[name] = 0

    def is_hex(s):
        try:
            unhexlify(s)
            return True
        except:
            return False

    badfiles = Queue()
    
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_file = {executor.submit(process_file, file, value, badfiles): file for file, value in chunks.items()}
        for future in as_completed(future_to_file):
            future.result()
 
    if not badfiles.empty():
        print("Bad File:")
    while not badfiles.empty():
        bad = badfiles.get()
        print(bad)