#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from io import BytesIO
from os import path, makedirs
from re import sub
from steam.core.crypto import symmetric_encrypt, symmetric_encrypt_with_iv
from struct import iter_unpack, pack
from sys import argv
from vdf import loads
from chunkstore import Chunkstore

def unpack_chunkstore(target, key=None, key_hex=None):
        chunkstore = Chunkstore(target)
        if key == True:
            key, key_hex = find_key(chunkstore.depot)
        with open(chunkstore.csdname, "rb") as csdfile:
            def unpacker(chunkstore, sha, offset, length):
                # print("extracting chunk %s from offset %s in file %s" % (hexlify(sha).decode(), offset, target + ".csd"))
                csdfile.seek(offset)
                if key:
                    if not path.exists("./depots/%s/%s" % (chunkstore.depot, hexlify(sha).decode())):
                        print("extracting chunk %s from offset %s in file %s" % (hexlify(sha).decode(), offset, target + ".csd"))
                        with open("./depots/%s/%s" % (chunkstore.depot, hexlify(sha).decode()), "wb") as f:
                            print("writing %s bytes re-encrypted using key %s and random IV" % (length, key_hex))
                            f.write(symmetric_encrypt(csdfile.read(length), key))
                elif chunkstore.is_encrypted:
                    if not path.exists("./depots/%s/%s" % (chunkstore.depot, hexlify(sha).decode())):
                        print("extracting chunk %s from offset %s in file %s" % (hexlify(sha).decode(), offset, target + ".csd"))
                        with open("./depots/%s/%s" % (chunkstore.depot, hexlify(sha).decode()), "wb") as f:
                            print("writing %s bytes encrypted" % length)
                            f.write(csdfile.read(length))
                else:
                    if not path.exists("./depots/%s/%s_decrypted" % (chunkstore.depot, hexlify(sha).decode())):
                        print("extracting chunk %s from offset %s in file %s" % (hexlify(sha).decode(), offset, target + ".csd"))
                        with open("./depots/%s/%s_decrypted" % (chunkstore.depot, hexlify(sha).decode()), "wb") as f:
                            print("writing %s bytes unencrypted" % length)
                            f.write(csdfile.read(length))
            makedirs("./depots/%s" % chunkstore.depot, exist_ok=True)
            chunkstore.unpack(unpacker)

def find_key(depot):
    if path.exists(f"./keys/{depot}.depotkey"):
        with open(f"./keys/{depot}.depotkey", "rb") as f:
            return unhexlify(f.read()), f.read()
    elif path.exists("./depot_keys.txt"):
        with open("./depot_keys.txt", "r", encoding="utf-8") as f:
            for line in f.read().split("\n"):
                line = line.split("\t")
                if line[0] == depot:
                    key_hex = line[2]
                    return unhexlify(key_hex), key_hex
    else:
        print("couldn't find key for depot", depot)
        exit(1)

def unpack_sis(sku, chunkstore_path, use_key = False):
    need_manifests = {}
    chunkstore_path = sub(r'Disk_\d+', '', chunkstore_path)
    if "sku" in sku.keys():
        sku = sku["sku"]

    # unpack each depot
    for depot in sku["manifests"]:
        key, key_hex = None, None
        if use_key and sku["backup"] == "1":
            key, key_hex = find_key(depot)
        need_manifests[depot] = sku["manifests"][depot]
        for chunkstore in sku["chunkstores"][depot]:
            print("unpacking chunkstore %s" % chunkstore)
            target = chunkstore_path + "/%s_depotcache_%s" % (depot, chunkstore)
            if not path.exists(target + ".csm"):
                # maybe it's in a disk folder?
                target = chunkstore_path + "/Disk_%s/%s_depotcache_%s" % (chunkstore, depot, chunkstore)
                if not path.exists(target + ".csm"):
                    # try again with other disk folders?
                    disk = 1
                    while disk <= int(sku["disks"]):
                        target = chunkstore_path + "/Disk_%s/%s_depotcache_%s" % (disk, depot, chunkstore)
                        print("searching for depot %s in disk %s" % (depot, disk))
                        if path.exists(target + ".csm"):
                            break
                        disk += 1
                    if not path.exists(target + ".csm"):
                        # welp
                        print("couldn't find depot %s chunkstore %s" % (depot, chunkstore))
                        return False
            # unpack this chunkstore
            unpack_chunkstore(target, key, key_hex)
    print("done unpacking, to extract with depot_extractor you will need these manifests:")
    for depot, manifest in need_manifests.items():
        print("depot %s manifest %s" % (depot, manifest))
    return True

if __name__ == "__main__":
    parser = ArgumentParser(description='Unpacks game data chunks from a SteamPipe retail master or game backup.')
    parser.add_argument("target", type=str, help="Path to the sku.sis file defining the master to unpack (or path to csd or csm file if only unpacking one chunkstore.)")
    parser.add_argument("-e", action='store_true', help="Re-encrypt the chunks with a key from depot_keys.txt (if one is available) after extracting. (The primary reason you would want to do this is to serve the chunks to a Steam client over a LAN cache.)", dest="key")
    args = parser.parse_args()
    if args.target.endswith(".sis"):
        with open(args.target, "r") as f:
            sku = loads(f.read())
        chunkstore_path = path.dirname(args.target)
        if chunkstore_path == "":
            chunkstore_path = "."
        exit(0 if unpack_sis(sku, chunkstore_path, args.key) else 1)
    else:
        unpack_chunkstore(args.target.replace(".csm","").replace(".csd",""), args.key)
