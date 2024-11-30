#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from os import scandir, makedirs, remove
from os.path import exists
from struct import pack, unpack, iter_unpack
from vdf import dumps
from sys import stderr
from chunkstore import Chunkstore
from steam.core.manifest import DepotManifest

def pack_backup(depot, destdir, decrypted=False, no_update=False, split=False, manifest_chunks=None, only_manifest=False):
    target_base = destdir + "/" + str(depot) + "_depotcache_"
    depot_dir = "./depots/" + str(depot)
    max_file_size = 1 * 1024 * 1024 * 1024  # 1 GiB
    file_index = 1
    csd_target = target_base + str(file_index) + ".csd"
    csm_target = target_base + str(file_index) + ".csm"
    mode = "wb"

    chunkstore = None
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
                file_index += 1
                csm_target = target_base + str(file_index) + ".csm"
                csd_target = target_base + str(file_index) + ".csd"
            # Reset file_index to the last valid index
            file_index -= 1
            csd_target = target_base + str(file_index) + ".csd"
            csm_target = target_base + str(file_index) + ".csm"
    if chunkstore is None:
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

    chunks = set()
    if manifest_chunks:
        chunks.update(manifest_chunks)

    if not only_manifest:
        cdn_chunks = [chunk.name for chunk in scandir(depot_dir) if chunk.is_file()
                      and not chunk.name.endswith(".zip")
                      and chunk_match(chunk.name)
                      and is_hex(chunk.name.replace("_decrypted", ""))
                      and not unhexlify(chunk.name.replace("_decrypted", "")) in chunkstore.chunks.keys()]
        chunks.update(cdn_chunks)
    
    chunks = sorted(chunks)

    csd = open(csd_target, mode)
    chunks_added = 0
    sizes = []
    for chunk in chunks:
        csd.seek(0, 2)
        offset = csd.tell()

        with open("./depots/" + str(depot) + "/" + chunk, "rb") as chunkfile:
            chunkfile.seek(0, 2)
            length = chunkfile.tell()
            chunkfile.seek(0)

            if split and offset + length > max_file_size:
                sizes.append(csd.tell())
                csd.close()
                chunkstore.write_csm()
                file_index += 1
                csd_target = target_base + str(file_index) + ".csd"
                csm_target = target_base + str(file_index) + ".csm"
                csd = open(csd_target, "wb")
                chunkstore = Chunkstore(csd_target, depot, not decrypted)
                offset = 0

            csd.write(chunkfile.read())

        if decrypted:
            chunkstore.chunks[unhexlify(chunk.replace("_decrypted", ""))] = (offset, length)
        else:
            chunkstore.chunks[unhexlify(chunk)] = (offset, length)
        chunks_added += 1
        print(f"depot {depot}: added chunk {chunk} ({chunks_added}/{len(chunks)})")
    sizes.append(csd.tell())
    csd.close()
    chunkstore.write_csm()
    print("writing index...")
    print("packed", len(chunks), "chunk" if len(chunks) == 1 else "chunks")
    return sizes

if __name__ == "__main__":
    parser = ArgumentParser(description='Pack a SteamPipe backup (.csd/.csm files, and optionally an sku.sis file defining the backup) from individual chunks in the depots/ folder.')
    parser.add_argument("-a", dest="appid", type=int, help="App ID for sku file (if ommitted, no sku will be generated)", nargs="?")
    parser.add_argument("-d", dest="depots", metavar=('depot', 'manifest'), action="append", type=int, help="Depot ID to pack, can be used multiple times. Include a manifest ID too if generating an sku.sis", nargs='+')
    parser.add_argument("-n", dest="name", default="steamarchiver backup", type=str, help="Backup name")
    parser.add_argument("--decrypted", action='store_true', help="Use decrypted chunks to pack backup", dest="decrypted")
    parser.add_argument("--no-update", action='store_true', help="If an existing backup is found, DELETE it instead of updating it", dest="no_update")
    parser.add_argument("--split", action='store_true', help="Enable 1 GiB file splitting", dest="split")
    parser.add_argument("--only-manifest", action='store_true', help="Only grab files listed in the manifest", dest="only_manifest")
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
            manifest_chunks = set()
            if (args.only_manifest):
                with open(manifest, "rb") as f:
                    manifest_data_source = f.read()
                    manifest_data = DepotManifest.deserialize(manifest_data_source)
                    if manifest_data.filenames_encrypted:
                        manifest_data.decrypt_filenames(args.depotkey)
                    for files in manifest_data.iter_files():
                        for chunk in sorted(files.chunks, key=lambda chunk: chunk.offset):
                            manifest_chunks.add(hexlify(chunk.sha).decode())
        else:
            depot = depot_tuple[0]
            manifest_chunks = None
        if write_sku:
            if manifest_chunks is None:
                write_sku = False
                print("not generating sku.sis: no manifest specified for depot", depot)
            else:
                sku["sku"]["depots"][len(sku["sku"]["depots"])] = str(depot)
                sku["sku"]["manifests"][str(depot)] = str(manifest)
        sizes = pack_backup(depot, args.destdir, args.decrypted, args.no_update, args.split, manifest_chunks, args.only_manifest)
        if write_sku:
            sku["sku"]["chunkstores"][str(depot)] = {str(i+1): str(size) for i, size in enumerate(sizes)}

    if write_sku:
        with open(args.destdir + "/sku.sis", "w") as skufile:
            skufile.write(dumps(sku, pretty=True))
            print("wrote sku.sis")
