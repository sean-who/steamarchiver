#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from os import scandir, makedirs, remove
from os.path import exists
from struct import pack, unpack, iter_unpack
from vdf import dumps
from sys import stderr
from chunkstore import Chunkstore

def pack_backup(depot, destdir, decrypted=False, no_update=False):
    target_base = destdir + "/" + str(depot) + "_depotcache_"
    depot_dir = "./depots/" + str(depot)
    max_file_size = 1 * 1024 * 1024 * 1024  # 1 GiB
    file_index = 1
    csd_target = target_base + str(file_index) + ".csd"
    csm_target = target_base + str(file_index) + ".csm"
    mode = "wb"

    if exists(csm_target) and exists(csd_target):
        if no_update: # don't want to update the old files, delete them
            remove(csd_target)
            remove(csm_target)
            mode = "wb"
        else:
            chunkstore = Chunkstore(csd_target, depot, not decrypted)
            chunkstore.unpack()
            mode = "ab"
            # Scan all existing .csm files
            while exists(csm_target):
                chunkstore.read_csm(csm_target)
                file_index += 1
                csm_target = target_base + str(file_index) + ".csm"
            # Reset file_index to the last valid index
            file_index -= 1
            csd_target = target_base + str(file_index) + ".csd"
            csm_target = target_base + str(file_index) + ".csm"
    else:
        chunkstore = Chunkstore(csd_target, depot, not decrypted)

    if decrypted:
        chunk_match = lambda chunk: chunk.endswith("_decrypted")
    else:
        chunk_match = lambda chunk: not chunk.endswith("_decrypted")

    def is_hex(s):
        try:
            unhexlify(s)
            return True
        except:
            return False

    chunks = [chunk.name for chunk in scandir(depot_dir) if chunk.is_file()
            and not chunk.name.endswith(".zip")
            and chunk_match(chunk.name)
            and is_hex(chunk.name.replace("_decrypted",""))
            and not unhexlify(chunk.name.replace("_decrypted","")) in chunkstore.chunks.keys()]

    csd = open(csd_target, mode)
    chunks_added = 0
    for chunk in chunks:
        csd.seek(0, 2)
        offset = csd.tell()

        with open("./depots/" + str(depot) + "/" + chunk, "rb") as chunkfile:
            chunkfile.seek(0, 2)
            length = chunkfile.tell()
            chunkfile.seek(0)

            if offset + length > max_file_size:
                csd.close()
                chunkstore.write_csm(csm_target)
                file_index += 1
                csd_target = target_base + str(file_index) + ".csd"
                csm_target = target_base + str(file_index) + ".csm"
                csd = open(csd_target, "wb")
                chunkstore = Chunkstore(csd_target, depot, not decrypted)
                offset = 0

            csd.write(chunkfile.read())

        if decrypted:
            chunkstore.chunks[unhexlify(chunk.replace("_decrypted",""))] = (offset, length)
        else:
            chunkstore.chunks[unhexlify(chunk)] = (offset, length)
        chunks_added += 1
        print(f"depot {depot}: added chunk {chunk} ({chunks_added}/{len(chunks)})")
    csd.close()
    chunkstore.write_csm(csm_target)
    print("writing index...")
    print("packed", len(chunks), "chunk" if len(chunks) == 1 else "chunks")
    return csd.tell()

if __name__ == "__main__":
    parser = ArgumentParser(description='Pack a SteamPipe backup (.csd/.csm files, and optionally an sku.sis file defining the backup) from individual chunks in the depots/ folder.')
    parser.add_argument("-a", dest="appid", type=int, help="App ID for sku file (if ommitted, no sku will be generated)", nargs="?")
    parser.add_argument("-d", dest="depots", metavar=('depot', 'manifest'), action="append", type=int, help="Depot ID to pack, can be used multiple times. Include a manifest ID too if generating an sku.sis", nargs='+')
    parser.add_argument("-n", dest="name", default="steamarchiver backup", type=str, help="Backup name")
    parser.add_argument("--decrypted", action='store_true', help="Use decrypted chunks to pack backup", dest="decrypted")
    parser.add_argument("--no-update", action='store_true', help="If an existing backup is found, DELETE it instead of updating it", dest="no_update")
    parser.add_argument("--destdir", help="Directory to put sis/csm/csd files in", default=".")
    args = parser.parse_args()
    makedirs(args.destdir, exist_ok=True)
    if args.depots == None:
        print("must specify at least one depot", file=stderr)
        parser.print_usage()
        exit(1)
    sku = {}
    write_sku = False
    if args.appid != None:
        write_sku = True
        sku = {"sku":
                {"name":args.name,
                "disks":"1",
                "disk":"1",
                "backup":"1" if args.decrypted else "0",
                "contenttype":"3",
                "apps":{
                    "0":str(args.appid)
                    },
                "depots":{},
                "manifests":{},
                "chunkstores":{}
              }
        }
    for depot_tuple in args.depots:
        if len(depot_tuple) == 2:
            depot, manifest = depot_tuple
        else:
            depot = depot_tuple[0]
            manifest = False
        if write_sku:
            if not manifest:
                write_sku = False
                print("not generating sku.sis: no manifest specified for depot",depot)
            else:
                sku["sku"]["depots"][len(sku["sku"]["depots"])] = str(depot)
                sku["sku"]["manifests"][str(depot)] = str(manifest)
        size = pack_backup(depot, args.destdir, args.decrypted, args.no_update)
        if write_sku:
            sku["sku"]["chunkstores"][str(depot)] = {"1":str(size)}
    if write_sku:
        with open(args.destdir + "/sku.sis", "w") as skufile:
            skufile.write(dumps(sku))
            print("wrote sku.sis")
