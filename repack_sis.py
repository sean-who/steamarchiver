#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify, unhexlify
from os import scandir, makedirs, remove
from os.path import exists
from struct import pack, unpack, iter_unpack
from vdf import dumps
from sys import stderr
from chunkstore import Chunkstore

def update_backup(depot, depotcache_dir, destdir, decrypted=False):
    # Define the base path for the target files
    target_base = destdir + "/" + str(depot) + "_depotcache_"
    depot_dir = "./depots/" + str(depot)
    depotcache_base = depotcache_dir + "/" + str(depot) + "_depotcache_"
    max_file_size = 1 * 1024 * 1024 * 1024  # 1 GiB
    file_index = 1
    csd_target = target_base + str(file_index) + ".csd"
    csm_target = target_base + str(file_index) + ".csm"
    csd_source = depotcache_base + str(file_index) + ".csd"
    csm_source = depotcache_base + str(file_index) + ".csm"
    mode = "wb"

    chunkstore = Chunkstore(csd_target, depot, not decrypted)
    depotcache_chunks = {}
    depotcache_chunks_source = {}

    # Process each csm file in the depotcache directory
    while exists(csm_source):
        with open(csm_source, "rb") as csm_file:
            chunkstore = Chunkstore(csd_target)  # Initialize with the current .csd file
            def unpacker(chunkstore, sha, offset, length):
                depotcache_chunks_source[sha] = (offset, length)
            chunkstore.unpack(unpacker)
            for chunk_id, (offset, length) in depotcache_chunks_source.items():
                depotcache_chunks[hexlify(chunk_id).decode()] = (csd_source, offset, length)
        file_index += 1
        csm_source = depotcache_base + str(file_index) + ".csm"
        csd_source = depotcache_base + str(file_index) + ".csd"

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

    # Collect all valid chunk files from the depot directory
    depot_chunks = [chunk.name for chunk in scandir(depot_dir) if chunk.is_file()
                    and not chunk.name.endswith(".zip")
                    and chunk_match(chunk.name)
                    and is_hex(chunk.name.replace("_decrypted",""))
                    and not unhexlify(chunk.name.replace("_decrypted","")) in depotcache_chunks.keys()]

    # Combine chunks, giving priority to depotcache chunks
    chunks = list(depotcache_chunks.keys()) + list([chunk for chunk in depot_chunks if chunk not in depotcache_chunks])
    chunks = sorted(chunks)

    csd = open(csd_target, mode)
    chunks_added = 0
    for chunk in chunks:
        csd.seek(0, 2)
        offset = csd.tell()

        if chunk in depotcache_chunks:
            csd_source, chunk_offset, length = depotcache_chunks[chunk]
            with open(csd_source, "rb") as source_file:
                source_file.seek(chunk_offset)
                data = source_file.read(length)
                csd.write(data)
        else:
            chunk_path = depot_dir + "/" + chunk
            with open(chunk_path, "rb") as chunkfile:
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
    parser = ArgumentParser(description='Update a SteamPipe backup (.csd/.csm files) from individual chunks in the depots/ folder and existing depotcache files.')
    parser.add_argument("-d", dest="depot", metavar='depot', type=int, help="Depot ID to update.", required=True)
    parser.add_argument("--depotcache", help="Directory containing existing depotcache files", required=True)
    parser.add_argument("--decrypted", action='store_true', help="Use decrypted chunks to update backup", dest="decrypted")
    parser.add_argument("--destdir", help="Directory to put csm/csd files in", default=".")
    args = parser.parse_args()
    makedirs(args.destdir, exist_ok=True)
    update_backup(args.depot, args.depotcache, args.destdir, args.decrypted)