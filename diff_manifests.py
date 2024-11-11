#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import unhexlify, hexlify
from datetime import datetime, timezone
from os.path import exists
from steam.core.manifest import DepotManifest
from sys import stderr

if __name__ == "__main__":
    parser = ArgumentParser(description='Generates a diff (comparison of changes) of two versions (manifests) of a Steam depot.')
    parser.add_argument("depotid", type=int, help="Depot ID to diff.")
    parser.add_argument("old", type=int, help="Old manifest to compare.")
    parser.add_argument("new", type=int, help="New manifest to compare.")
    parser.add_argument("-q", action="store_true", help="quiet: only output errors and names of added or modified files", dest="quiet")
    parser.add_argument("-d", action="store_true", help="detailed: print the sha1 checksums of added/removed chunks", dest="detailed")
    args = parser.parse_args()
    keyfile = "./keys/%s.depotkey" % args.depotid
    oldpath = f"./depots/{args.depotid}/{args.old}.zip"
    newpath = f"./depots/{args.depotid}/{args.new}.zip"
    if not exists(oldpath):
        print(f"manifest {args.old} not found", file=stderr)
        exit(1)
    if not exists(newpath):
        print(f"manifest {args.new} not found", file=stderr)
        exit(1)
    with open(oldpath, "rb") as f:
        old = DepotManifest(f.read())
    with open(newpath, "rb") as f:
        new = DepotManifest(f.read())
    if (old.filenames_encrypted or new.filenames_encrypted):
        if exists(keyfile):
            with open(keyfile, "rb") as f:
                key = f.read()
        elif exists("./depot_keys.txt"):
            with open("./depot_keys.txt", "r", encoding="utf-8") as f:
                for line in f.read().split("\n"):
                    line = line.split("\t")
                    if line[0] == str(args.depotid):
                        key = unhexlify(line[2])
        if key:
            old.decrypt_filenames(key)
            new.decrypt_filenames(key)
        if (old.filenames_encrypted or new.filenames_encrypted):
            print("unable to decrypt filenames, missing depot key", file=stderr)
            exit(1)

    format_bytes = lambda num_bytes: f"{num_bytes:,} {'byte' if num_bytes == 1 else 'bytes'}"
    old_files = {}
    old_chunks = {}
    old_size_original, old_size_compressed = 0, 0
    for file in old.iter_files():
        old_files[file.filename] = file
        for chunk in file.chunks:
            if not chunk.sha in old_chunks.keys():
                old_chunks[chunk.sha] = chunk
                old_size_original += chunk.cb_original
                old_size_compressed += chunk.cb_compressed
    if not args.quiet:
        print(f"Comparing depot {args.depotid} old version {old.gid} ({datetime.fromtimestamp(old.creation_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}) with new version {new.gid} ({datetime.fromtimestamp(new.creation_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')})")
        print("List of changed files:")
    num_new_chunks, size_new_chunks = 0, 0
    num_reused_chunks, size_reused_chunks = 0, 0
    num_deleted_chunks, size_deleted_chunks = 0, 0
    new_size_original, new_size_compressed = 0, 0
    chunks_found = []
    for file in new.iter_files():
        for chunk in file.chunks:
            if not chunk.sha in old_chunks.keys():
                if not chunk.sha in chunks_found:
                    num_new_chunks += 1
                    size_new_chunks += chunk.cb_original
                    chunks_found.append(chunk.sha)
                    if args.detailed: print("added chunk", hexlify(chunk.sha).decode())
                    new_size_original += chunk.cb_original
                    new_size_compressed += chunk.cb_compressed
            else:
                del old_chunks[chunk.sha]
                if not chunk.sha in chunks_found:
                    chunks_found.append(chunk.sha)
                    num_reused_chunks += 1
                    size_reused_chunks += chunk.cb_original
                    new_size_original += chunk.cb_original
                    new_size_compressed += chunk.cb_compressed
        if not file.filename in old_files.keys():
            if args.quiet:
                print(file.filename)
            else:
                print(f"added file {file.filename} ({format_bytes(file.size)} in {len(file.chunks)} {'chunk' if len(file.chunks) == 1 else 'chunks'})")
        else:
            old_file = old_files[file.filename]
            del old_files[file.filename]
            if old_file.chunks != file.chunks:
                if args.quiet:
                    print(file.filename)
                else:
                    print(f"modified file {file.filename}")
                    print(f"\told: {format_bytes(old_file.size)} in {len(old_file.chunks)} {'chunk' if len(old_file.chunks) == 1 else 'chunks'}")
                    size_diff = file.size - old_file.size
                    print(f"\tnew: {format_bytes(file.size)} ({'+' if size_diff > 0 else '+-' if size_diff == 0 else ''}{size_diff} {'byte' if size_diff == 1 else 'bytes'}) in {len(file.chunks)} {'chunk' if len(file.chunks) == 1 else 'chunks'}")
    if not args.quiet:
        for filename, file in old_files.items():
            print(f"deleted file {filename}")
        print("End list of changed files.")
        for _, chunk in old_chunks.items():
            num_deleted_chunks += 1
            if args.detailed: print("deleted chunk", hexlify(chunk.sha).decode())
            size_deleted_chunks += chunk.cb_original
        size_diff_original = new_size_original - old_size_original
        size_diff_compressed = new_size_compressed - old_size_compressed
        print("Download size stats:")
        print(f"Old version totals {format_bytes(old_size_original)} uncompressed, {format_bytes(old_size_compressed)} compressed ({round(old_size_compressed/old_size_original*100, 2)}% ratio)")
        print(f"New version totals {format_bytes(new_size_original)} uncompressed ({'+' if size_diff_original > 0 else '+-' if size_diff_original == 0 else ''}{format_bytes(size_diff_original)}), {format_bytes(new_size_compressed)} compressed ({round(new_size_compressed/new_size_original*100, 2)}% ratio)")
        print(f"{format_bytes(size_new_chunks)} added in {num_new_chunks} {'chunk' if num_new_chunks == 1 else 'chunks'}")
        print(f"{format_bytes(size_reused_chunks)} reused in {num_reused_chunks} {'chunk' if num_reused_chunks == 1 else 'chunks'}")
        print(f"{format_bytes(size_deleted_chunks)} deleted in {num_deleted_chunks} {'chunk' if num_deleted_chunks == 1 else 'chunks'}")
        print(f"End diff of depot {args.depotid} old version {old.gid} ({datetime.fromtimestamp(old.creation_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}) with new version {new.gid} ({datetime.fromtimestamp(new.creation_time, timezone.utc).strftime('%Y-%m-%d %H:%M:%S')})")        
