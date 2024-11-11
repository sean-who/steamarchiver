#!/usr/bin/env python3
from binascii import hexlify, unhexlify
from os import path
from struct import iter_unpack, pack
from sys import argv

class Chunkstore():
    def __init__(self, filename, depot=None, is_encrypted=None):
        filename = filename.replace(".csd","").replace(".csm","")
        self.csmname = filename + ".csm"
        self.csdname = filename + ".csd"
        self.chunks = {}
        if path.exists(self.csdname) and path.exists(self.csmname):
            with open(self.csmname, "rb") as csmfile:
                self.csm = csmfile.read()
                if self.csm[:4] != b"SCFS":
                    print("not a CSM file: " + (filename + ".csm"))
                    return False
                self.depot = int.from_bytes(self.csm[0xc:0x10], byteorder='little', signed=False)
                self.is_encrypted = (self.csm[0x8:0xa] == b'\x03\x00')
                if is_encrypted != None and self.is_encrypted != is_encrypted:
                    raise Exception("chunkstore " + self.csdname + " already exists and contains " + ("encrypted" if self.is_encrypted else "decrypted") + " chunks")
                if depot != None and self.depot != depot:
                    raise Exception("chunkstore " + self.csdname + " already exists and lists a different depot (" + str(self.depot) + " instead of " + str(depot) + ")")
        elif depot != None and is_encrypted != None:
            self.depot = depot
            self.is_encrypted = is_encrypted
        else:
            raise Exception("Need to specify depot and encryption if file doesn't already exist")
    def __repr__(self):
        return f"Depot {self.depot} (encrypted: {self.is_encrypted}, chunks: {len(self.chunks)}) from CSD file {self.csdname}"
    def unpack(self, unpacker=None):
        if unpacker: assert callable(unpacker)
        self.chunks = {}
        with open(self.csmname, "rb") as csmfile: csm=csmfile.read()[0x14:]
        for sha, offset, _, length in iter_unpack("<20s Q L L", csm):
            self.chunks[sha] = (offset, length)
            if unpacker: unpacker(self, sha, offset, length)
    def write_csm(self):
        # write CSM header
        with open(self.csmname, "wb") as csmfile:
            csmfile.write(b"SCFS\x14\x00\x00\x00")
            if self.is_encrypted:
                csmfile.write(b"\x03\x00\x00\x00")
            else:
                csmfile.write(b"\x02\x00\x00\x00")
            csmfile.write(pack("<L L", self.depot, len(self.chunks)))
            csmfile.seek(0, 2) # make sure we're at the end of the csm file (in case we're writing to an existing csm)
            # iterate over chunks
            for sha, (offset, length) in self.chunks.items():
                csmfile.write(sha)
                csmfile.write(pack("<Q L L", offset, 0, length))
    def get_chunk(self, sha):
        with open(self.csdname, "rb") as csdfile:
            csdfile.seek(self.chunks[sha][0])
            return csdfile.read(self.chunks[sha][1])

if __name__ == "__main__":
    if len(argv) > 1:
        chunkstore = Chunkstore(argv[1])
        chunkstore.unpack()
        print(chunkstore)
