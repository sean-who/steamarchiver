# steamarchiver

A set of utilities to preserve Steam content, including tools to archive app
information, archive depots in SteamPipe CDN content and extract them, and
download versions of the Steam client.

Patches and feedback can go to [the mailing
list](https://lists.sr.ht/~technomage6/steamarchiver).

This is a Fork of [Steam Archive](https://git.sr.ht/~blowry/steamarchiver) by Blowry.

Special credit goes to [SolsticeGameStudio](https://github.com/solsticegamestudios/steam)
for maintaining a current fork of the ValvePython library and keeping it current.

## Usage

For the Python scripts, install the requirements:

``pip3 install -r requirements.txt``

Many scripts require authentication, which can be passed on the command line
using the ``-u [username]`` flag. ``-p [password]`` will allow you to pass the
password on the command line as well; if you do not do this, you will be
interactively prompted for a password.

Usage for the Python scripts:

- ``depot_archiver.py`` downloads depots (the logical groupings of game content
  files Steam delivers). You can give it an appid, in which case it'll download
  the latest depots for that app, or you can give it a specific appid, depotid,
  and manifest number (manifests are specific versions of depots.) It will
  download the manifest, appinfo, and encrypted depot chunks. **Ownership of an
  app is required to download its manifest; you can only download an app without
  logging in if its manifest has previously been downloaded. Most (non-dedicated
  server, non-Valve) free apps are not available to anonymous users; you will
  still need to log into an account to download free games!**
  ``depot_validator.py`` verifies every chunk in a depot folder to ensure none of
  the files are corrupted or bad.
- ``get_depot_keys.py`` logs into a Steam account and dumps all the depot keys
  it has access to, which can be used to decrypt downloaded depots. To get the
  key for a depot, your account must own a package that includes access to the
  depot, and it must also own a package that includes an app which specifies the
  depot should be installed; you cannot get keys for depots you have access to
  that aren't included in any released apps, since that's how Steam prevents you
  from decrypting preloaded game content. Keys will be saved to depot_keys.txt
- ``depot_extractor.py`` extracts downloaded depots. It requires the key but can
  work completely offline.
- ``list_downloaded_manifests.py`` can be used to verify if a particular
  depot/manifest has been downloaded, or it can list out the manifests used by
  branches of an app and check if they've been downloaded.
- ``get_appinfo.py`` downloads the latest appinfo for the specified apps, or for
  all publicly visible apps if run with no arguments.
- ``update_appinfo.py`` attempts to download appinfo for only the apps that have
  changes since the last time get_appinfo was run.
- ``get_client.py`` downloads the manifest for the Steam client and downloads
  all needed packages. When run without arguments it'll download the release
  version of the Steam client for Win32; you can also specify a different
  channel, e.g. ``get_client.py steam_client_ubuntu12``, ``get_client.py
  steam_client_publicbeta_osx``, ``get_client.py steam_cmd_linux``,
  ``get_client.py steamchina_win32``, etc.
- ``unpack_sis.py`` unpacks a Steam game backup or retail master (which consists
  of a sku.sis manifest, csd files containing depot data, and cdm files
  containing metadata about the locations of chunks in the csd.) Unpacking with
  this script is free, but for actually extracting the data afterward with
  depot_extractor you need to have a downloaded copy of the manifest (you can
  get one by running depot_archiver in dry run mode, using the -d flag) and the
  decryption key.
- ``pack_sis.py`` goes the other way, packing depot chunks from a depots/
  subfolder into .csd and .csm archive files. This is useful for transferring
  (as moving two files is usually much faster than moving a couple thousand), or
  for restoring a backup using the Steam client (requires specifying a depot
  manifest so an sku.sis file can be generated.)
- ``diff_manifests.py`` displays the difference between two manifests of the
  same depot, showing which files were added/changed/removed, the download size
  of the depot, and the change in on-disk size after download.
- ``steam_websocket_mitm.py`` is an mitmproxy script to inspect Steam's
  WebSockets network traffic. This is only really useful for debugging.
- ``login.py`` runs an interactive login for testing purposes.
- ``chunkstore.py`` loads a .csd/.csm and lists the depot ID, encryption, and
  number of chunks without unpacking anything.

The folder steamlancache contains an HTTP server (written in Golang) that you
can use as a LAN cache for Steam to speed up downloads and automatically archive
all the content you download in the formats these scripts expect. Just run the
server with the folder the Python scripts are in as the working directory, and
set a DNS record to point "lancache.steamcontent.com" to the IP of the server.

For help finding appids, depotids, and manifestids, check out
https://steamdb.info (requires logging in with a non-limited Steam account to
view older manifests)

## Example

Get all the depot keys available to anonymous users:

    python3 get_depot_keys.py

Log into a specific account and get all its depot keys:

    python3 get_depot_keys.py -u [username] -p [password]

Download all the depots for Team Fortress 2:

    python3 depot_archiver.py -a 440

Download the Team Fortress 2 Linux client binaries that were released at
2022-08-11 22:29:49:

    python3 depot_archiver.py -a 440 232253 5841585021586447253

Extract those binaries:

    python3 depot_extractor.py 232253 5841585021586447253 bdbeae4f56fa865d8df2f76623d3346fcd7e56df6dee13b0f23e4a0fe160a446

(Note: the key for the above command was found in depot_keys.txt, in this line:)

    232253		bdbeae4f56fa865d8df2f76623d3346fcd7e56df6dee13b0f23e4a0fe160a446	TF2 Linux client

## License

   Copyright 2021-2023 Benjamin Lowry

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
