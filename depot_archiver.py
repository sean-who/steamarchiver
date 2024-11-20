#!/usr/bin/env python3
from argparse import ArgumentParser
from asyncio import run, gather, sleep
from binascii import hexlify, unhexlify
from datetime import datetime
from math import ceil
from os import makedirs, path, listdir, remove
from sys import argv
import logging

_LOG = logging.getLogger("DepotArchiver")

if __name__ == "__main__": # exit before we import our shit if the args are wrong
    parser = ArgumentParser(description='Download Steam content depots for archival. Downloading apps: Specify an app to download all the depots for that app, or an app and depot ID to download the latest version of that depot (or a specific version if the manifest ID is specified.) Downloading workshop items: Use the -w flag to specify the ID of the workshop file to download. Exit code is 0 if all downloads succeeded, or the number of failures if at least one failed.')
    dl_group = parser.add_mutually_exclusive_group()
    log_group = parser.add_mutually_exclusive_group()
    dl_group.add_argument("-a", type=int, dest="downloads", metavar=("appid","depotid"), action="append", nargs='+', help="App, depot, and manifest ID to download. If the manifest ID is omitted, the lastest manifest specified by the public branch will be downloaded.\nIf the depot ID is omitted, all depots specified by the public branch will be downloaded.")
    dl_group.add_argument("-w", type=int, nargs='?', help="Workshop file ID to download.", dest="workshop_id")
    parser.add_argument("--anon", "--anonymous", action="store_true", help="Logs in Anonymously. Only used for public accessible files.")
    parser.add_argument("-r", type=str, nargs='?', help="Branch Name.", dest="branch")
    parser.add_argument("-n", type=str, nargs='?', help="Branch Password", dest="bpassword")
    parser.add_argument("-b", help="Download into a Steam backup file instead of storing the chunks individually", dest="backup", action="store_true")
    parser.add_argument("-e", type=str, nargs='?', help="Specifies the encrypted Manifest ID to be decrypted by the branch password.", dest="encryptedbranch")
    # parser.add_argument("--redownload", help="Redownloads all files, regardless if it is good or bad.", action="store_true")
    parser.add_argument("-d", help="Dry run: download manifest (file metadata) without actually downloading files", dest="dry_run", action="store_true")
    parser.add_argument("-l", help="Use latest local appinfo instead of trying to download", dest="local_appinfo", action="store_true")
    parser.add_argument("-c", type=int, help="Number of concurrent downloads to perform at once, default 10", dest="connection_limit", default=10)
    parser.add_argument("-s", type=str, help="Specify a specific server URL instead of automatically selecting one, e.g. https://steampipe.akamaized.net", nargs='?', dest="server")
    parser.add_argument("-i", help="Log into a Steam account interactively.", dest="interactive", action="store_true")
    parser.add_argument("-u", type=str, help="Username for non-interactive login", dest="username", nargs="?")
    parser.add_argument("-p", type=str, help="Password for non-interactive login", dest="password", nargs="?")
    log_group.add_argument("--debug", help="Enable debug logging", action="store_true")
    log_group.add_argument("--info", help="Enable info logging", action="store_true")
    args = parser.parse_args()
    if args.connection_limit < 1:
        print("connection limit must be at least 1")
        parser.print_help()
        exit(1)
    if not args.downloads and not args.workshop_id:
        print("must specify at least one appid or workshop file id")
        parser.print_help()
        exit(1)
    if args.downloads and args.workshop_id:
        print("must specify only app or workshop item, not both")
        parser.print_help()
        exit(1)
    if args.branch and args.workshop_id:
        print("The Workshop doesn't have branches. Unable to continue")
        parser.print_help()
        exit(1)
    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    elif args.info:
        logging.basicConfig(level=logging.INFO)
    # if args.branch and not args.bpassword:
    #     print("You need a password in order to download from a non-Public Branch")
    #     parser.print_help()
    #     exit(1)

from steam.client import SteamClient
from steam.client.cdn import CDNClient, CDNDepotManifest
from steam.core.msg import MsgProto
from steam.core.crypto import symmetric_decrypt_ecb
from steam.enums import EResult
from steam.enums.emsg import EMsg
from steam.exceptions import SteamError
from steam.protobufs.content_manifest_pb2 import ContentManifestPayload
from vdf import loads
from aiohttp import ClientSession
from login import auto_login
from chunkstore import Chunkstore

def archive_manifest(manifest, c, name="unknown", dry_run=False, server_override=None, backup=False):
    if not manifest:
        return False
    print("Archiving", manifest.depot_id, "(%s)" % (name), "gid", manifest.gid, "from", datetime.fromtimestamp(manifest.creation_time))
    dest = "./depots/" + str(manifest.depot_id) + "/"
    makedirs(dest, exist_ok=True)
    if dry_run:
        print("Not downloading chunks (dry run)")
        return True
    if backup:
        chunkstore = Chunkstore(str(manifest.depot_id) + "_depotcache_1.csm", depot=manifest.depot_id, is_encrypted=True)
        if path.exists(chunkstore.csdname): chunkstore.unpack()
        csdfile = open(chunkstore.csdname, "ab")
    else:
        chunkstore, csdfile = None, None
    known_chunks = []
    for file in manifest.payload.mappings:
        for chunk in file.chunks:
            known_chunks.append(chunk.sha)
    print("Beginning to download", len(known_chunks), "encrypted", "chunk" if len(known_chunks) == 1 else "chunks")
    class download_state():
        def __init__(self):
            self.chunks_dled = 0
            self.chunks_skipped = 0
            self.bytes = 0
    download_state = download_state()
    async def dl_worker(chunks, download_state, servers, chunkstore=None, csdfile=None):
        server = servers[0]
        async with ClientSession() as session:
            for index, chunk in enumerate(chunks):
                # chunkstr = hexlify(chunk).decode()
                # dest = dest + chunkstr[:3] + "/" + chunkstr[3:6] + "/"
                if path.exists(dest + hexlify(chunk).decode()) or (chunkstore and (chunk in chunkstore.chunks.keys())):
                    download_state.chunks_skipped += 1
                    del chunks[index]
            for chunk in chunks:
                chunk_str = hexlify(chunk).decode()
                # dest = dest + chunk_str[:3] + "/" + chunk_str[3:6] + "/"
                if path.exists(dest + chunk_str) or (chunkstore and (chunk in chunkstore.chunks.keys())):
                    download_state.chunks_skipped += 1
                    continue
                while True:
                    try:
                        if server_override:
                            request_url = "%s/depot/%s/chunk/%s" % (server_override, manifest.depot_id, chunk_str)
                            host = server.host
                        else:
                            request_url = "%s://%s:%s/depot/%s/chunk/%s" % ("https" if server.https else "http",
                                server.host,
                                server.port,
                                manifest.depot_id,
                                chunk_str)
                            host = ("https" if server.https else "http") + "://" + server.host
                        async with session.get(request_url) as response:
                            if response.ok:
                                download_state.bytes += response.content_length
                                content = await response.content.read()
                                break
                            if response.status == 404:
                                print("rotating to next server")
                                servers.rotate(-1)
                                server = servers[0]
                                continue
                            elif 400 <= response.status < 500:
                                print(f"\033[31merror: received status code {response.status} (on chunk {chunk_str}, server {host})\033[0m")
                                return False
                    except Exception as e:
                        print("rotating to next server:", e)
                    servers.rotate(-1)
                    server = servers[0]
                    await sleep(0.5)
                if not csdfile: f = open(dest + chunk_str, "wb")
                else: f = csdfile
                f.seek(0, 2)
                offset = f.tell()
                length = f.write(content)
                if chunkstore:
                    chunkstore.chunks[chunk] = (offset, length)
                if not csdfile: f.close()
                download_state.chunks_dled += 1
    async def summary_printer(download_state):
        averages = []
        last_msg_length = 0
        while download_state.chunks_dled + download_state.chunks_skipped != len(known_chunks):
            averages.append(download_state.bytes)
            download_state.bytes = 0
            if len(averages) == 6:
                del averages[0]
            speed = 0
            for average in averages:
                speed += average
            speed = round(speed / len(averages) / 1000000, 2)
            msg = f"\rDownloading at {speed}MB/s ({download_state.chunks_dled + download_state.chunks_skipped}/{len(known_chunks)})"
            if last_msg_length > len(msg):
                whitespace = " " * (last_msg_length - len(msg))
            else:
                whitespace = ""
            print(msg + whitespace,end="")
            last_msg_length = len(msg)
            await sleep(1)

    async def run_workers(download_state):
        workers = [summary_printer(download_state)]
        chunk_size = int(ceil(len(known_chunks)/args.connection_limit))
        for i in range(args.connection_limit):
            workers.append(dl_worker(known_chunks[i * chunk_size:i * chunk_size + chunk_size], download_state, c.servers.copy(), chunkstore, csdfile))
        await gather(*workers)

    run(run_workers(download_state))
    if chunkstore:
        chunkstore.write_csm()
        csdfile.close()
    print("\nFinished downloading", manifest.depot_id, "(%s)" % (name), "gid", manifest.gid, "from", datetime.fromtimestamp(manifest.creation_time))
    print("Downloaded %s %s and skipped %s" % (download_state.chunks_dled, "chunk" if download_state.chunks_dled == 1 else "chunks", download_state.chunks_skipped))
    return True

def try_load_manifest(appid, depotid, manifestid, branch='public', password=None):
    print(f"Getting a manifest for app {appid} depot {depotid} gid {manifestid}")
    dest = "./depots/%s/%s.zip" % (depotid, manifestid)
    makedirs("./depots/%s" % depotid, exist_ok=True)
    if path.exists(dest):
        with open(dest, "rb") as f:
            print("Loaded cached manifest %s from disk" % manifestid)
            return CDNDepotManifest(c, appid, f.read())
    else:
        retry = 0
        while True:
            license_requested = False
            try:
                depotid = int(depotid)
                request_code = c.get_manifest_request_code(appid, depotid, manifestid, branch, password)
                print("Obtained code", request_code, "for depot", depotid, "valid as of", datetime.now())
                resp = c.cdn_cmd('depot', '%s/manifest/%s/5/%s' % (depotid, manifestid, request_code), appid, depotid)
                if not resp.ok:
                    print("Got status code", resp.status_code, resp.reason, "trying to download depot", depotid, "manifest", manifestid)
                    return False
                break
            except SteamError as e:
                if e.eresult == EResult.AccessDenied:
                    # if result is not None and result == EResult.RateLimitExceeded:
                    #     print("Rate Limit Exceeded")
                    #     return False
                    if not license_requested and retry < 2:
                        result, granted_appids, granted_packageids = steam_client.request_free_license([appid])
                        retry += 1
                        license_requested = True
                        continue
                    print(e.message + ": " + EResult(e.eresult).name)
                    print(f"Use the -i flag to log into a Steam account with access to this depot, or place a downloaded copy of the manifest at depots/{depotid}/{manifestid}.zip")
                    return False
                elif e.eresult == EResult.Timeout:
                    steam_client.reconnect()
                    continue
                else:
                    print(e.message + ": " + str(e.eresult))
                    return False
        print("Downloaded manifest %s" % manifestid)
        print("Saving manifest...") # write manifest to disk. this will be a standard Zip with protobuf data inside
        with open(dest, "wb") as f:
            f.write(resp.content)
        return CDNDepotManifest(c, appid, resp.content)

def get_gid(manifest):
    if type(manifest) == str:
        return int(manifest)
    elif type(manifest) == int:
        return manifest
    else:
        return manifest["gid"]

## Steam's own function, check_beta_password, will always only return resp.eresult.
## It never returns the beta_passwords.
def beta_check_password(app_id, password, c):
    """Check branch beta password to unlock encrypted branches

    :param app_id: App ID
    :type  app_id: int
    :param password: beta password
    :type  password: str
    :returns: result
    :rtype: :class:`.EResult`
    """
    beta_passwords = {}
    resp = c.steam.send_job_and_wait(MsgProto(EMsg.ClientCheckAppBetaPassword),
                                        {'app_id': app_id, 'betapassword': password})

    if resp.eresult == EResult.OK:
        print("Unlocked following beta branches: ",
                        ', '.join(map(lambda x: x.betaname.lower(), resp.betapasswords)))
        for entry in resp.betapasswords:
            beta_passwords[(app_id, entry.betaname.lower())] = unhexlify(entry.betapassword)
            return beta_passwords
    else:
        print("App beta password check failed. %r" % EResult(resp.eresult))
        # return EResult(resp.eresult)
        exit(1)

def get_depotkeys(app, depot):
    # key_text = False
    makedirs("./keys", exist_ok=True)
    key_binary = False
    keyfile = "./keys/%s.depotkey" % depot
    # keys_saved = []
    # key = 0
    # Checking if either depot key within depot_key.txt or the depot's binary key file exists
    # if path.exists("./depot_keys.txt"):
    #     with open("./depot_keys.txt", "r", encoding="utf-8") as f:
    #         for line in f.read().split("\n"):
    #             try:
    #                 keys_saved.append(int((line.split("\t")[0])))
    #             except ValueError:
    #                 pass
    #         for line in keys_saved:
    #             try:
					# Keep getting TypeError: 'int' object is not subscriptable
					# Disabled all portions the read/write text file until fixed.
    #                 if int(line[0]) == depot:
    #                     key = bytes.fromhex(line[2])
    #                     key_text = True
    #                     break
    #             except ValueError:
    #                 pass
    #     # print("%s keys already saved in depot_keys.txt" % len(keys_saved))
    if path.exists(keyfile):
        key_binary = True
    
    # If neither exist
    if not key_binary:
        try:
            depot = int(depot)
            key = steam_client.get_depot_key(app, depot).depot_encryption_key
        except AttributeError:
            print("error getting key for depot", depot)
        with open(keyfile, "wb") as f:
            try:
                f.write(key)
            except Exception as e:
                print("\033[31mError writing key file:\033[0m", e)
            f.close()
        return
    
    # If the text file exists but not the binary
    # grab it from the text file and write it to the binary
    # if key_text and not key_binary:
    #     with open(keyfile, "wb") as f:
    #         try:
    #             f.write(key)
    #         except Exception as e:
    #             print("\033[31mError writing to binary key file.\033[0m", e)
    #     return
    
    # If the binary file exists but not the text
    # grab it from the binary and write it to the text file
    # if key_binary and not key_text:
    #     with open(keyfile, "rb") as f:
    #         key = f.read()
    #     with open("./depot_keys.txt", "a", encoding="utf-8", newline="\n") as f:
    #         if key != b'':
    #             key_hex = hexlify(key).decode()
    #             f.write("%s\t\t%s" % (depot, key_hex) + "\n")
    #             print("%s\t\t%s" % (depot, key_hex))
    #     return

if __name__ == "__main__":
    # Create directories
    makedirs("./appinfo", exist_ok=True)
    makedirs("./depots", exist_ok=True)

    steam_client = SteamClient()
    print("Connecting to the Steam network...")
    steam_client.connect()
    print("Logging in...")
    if args.interactive:
        auto_login(steam_client, fallback_anonymous=False, relogin=False)
    elif args.username:
        auto_login(steam_client, args.username, args.password)
    elif args.anon:
        auto_login(steam_client, fallback_anonymous=True)
    else:
        auto_login(steam_client)
    c = CDNClient(steam_client)

    if args.workshop_id:
        response = steam_client.send_um_and_wait("PublishedFile.GetDetails#1", {'publishedfileids':[args.workshop_id]})
        if response.header.eresult != EResult.OK:
            print("\033[31merror: couldn't get workshop item info:\033[0m", response.header.error_message)
            exit(1)
        file = response.body.publishedfiledetails[0]
        if file.result != EResult.OK:
            print("\033[31merror: steam returned error\033[0m", EResult(file.result))
            exit(1)
        print("Retrieved data for workshop item", file.title, "for app", file.consumer_appid, "(%s)" % file.app_name)
        if not file.hcontent_file:
            print("\033[31merror: workshop item is not on SteamPipe\033[0m")
            exit(1)
        if file.file_url:
            print("\033[31merror: workshop item is not on SteamPipe: its download URL is\033[0m", file.file_url)
            exit(1)
        archive_manifest(try_load_manifest(file.consumer_appid, file.consumer_appid, file.hcontent_file), c, file.title, args.dry_run, args.server, args.backup)
        exit(0)

    # Iterate over all the downloads we want
    exit_status = 0
    for dl_tuple in args.downloads:
        appid = dl_tuple[0]
        depotid = (dl_tuple[1] if len(dl_tuple) > 1 else None)
        manifestid = (dl_tuple[2] if len(dl_tuple) > 2 else None)

        # Fetch appinfo
        if args.local_appinfo:
            highest_changenumber = 0
            for file in listdir("./appinfo/"):
                if not file.endswith(".vdf"): continue
                if not file.startswith(str(appid) + "_"): continue
                changenumber = int(file.split("_")[1].replace(".vdf", ""))
                if changenumber > highest_changenumber:
                    highest_changenumber = changenumber
            if highest_changenumber == 0:
                print("\033[31merror: -l flag specified, but no local appinfo exists for app\033[0m", appid)
                exit(1)
            appinfo_path = "./appinfo/%s_%s.vdf" % (appid, highest_changenumber)
        else:
            print(f"Is the client logged in? {steam_client.logged_on}")
            print("Fetching appinfo for", appid)
            tokens = steam_client.get_access_tokens(app_ids=[appid])
            msg = MsgProto(EMsg.ClientPICSProductInfoRequest)
            body_app = msg.body.apps.add()
            body_app.appid = appid
            if 'apps' in tokens.keys() and appid in tokens['apps'].keys():
                body_app.access_token = tokens['apps'][appid]
            appinfo_response = steam_client.wait_event(steam_client.send_job(msg))[0].body.apps[0]
            changenumber = appinfo_response.change_number
            # Write vdf appinfo to disk
            appinfo_path = "./appinfo/%s_%s.vdf" % (appid, changenumber)
        need_to_write_appinfo = True
        if path.exists(appinfo_path):
            with open(appinfo_path, "r", encoding="utf-8") as f:
                appinfo = loads(f.read())['appinfo']
            if 'public_only' in appinfo.keys():
                if appinfo['public_only'] == '1':
                    print("Replacing public_only appinfo at:", appinfo_path)
                    remove(appinfo_path)
            else:
                need_to_write_appinfo = False
        if need_to_write_appinfo:
            with open(appinfo_path, "wb") as f:
                f.write(appinfo_response.buffer[:-1])
            print("Saved appinfo for app", appid, "changenumber", changenumber)
            # decode appinfo
            appinfo = loads(appinfo_response.buffer[:-1].decode('utf-8', 'replace'))['appinfo']
        if "public_only" in appinfo.keys():
            print("WARNING: this app has additional (private) info. The archive "
                    "may not work due to this info being missing. To get this "
                    "info, run get_appinfo.py on this app using an account "
                    "authorized to access it.")

        if depotid:
            name = appinfo['depots'][str(depotid)]['name'] if 'name' in appinfo['depots'][str(depotid)] else 'unknown'
            get_depotkeys(appid, depotid)
            if manifestid:
                print("Archiving", appinfo['common']['name'], "depot", depotid, "manifest", manifestid)
                exit_status += (0 if archive_manifest(try_load_manifest(appid, depotid, manifestid, args.branch), c, name, args.dry_run, args.server, args.backup) else 1)
            elif args.branch and args.bpassword:
                try:
                    branch_key = beta_check_password(appid, args.bpassword, c)
                    if args.encryptedbranch != '':
                        encrypted_manifest = args.encryptedbranch
                    else:
                        encrypted_manifest = get_gid(appinfo['depots'][str(depotid)]['encryptedmanifests'][args.branch])
                    manifestid = int.from_bytes(symmetric_decrypt_ecb(unhexlify(encrypted_manifest),branch_key[(appid, args.branch)]),byteorder='little')
                    print("Archiving", appinfo['common']['name'], "depot", depotid, "branch", args.branch, "manifest", manifestid, "using key", branch_key)
                    exit_status += (0 if archive_manifest(try_load_manifest(appid, depotid, manifestid, args.branch, args.bpassword), c, name, args.dry_run, args.server, args.backup) else 1)
                    # exit_status += (0 if archive_manifest(try_load_manifest(appid, depotid, manifestid, args.branch, branch_key), c, name, args.dry_run, args.server, args.backup) else 1)
                except SteamError as e:
                    print(f"Error:", e)
                    exit(1)
            else:
                manifest = get_gid(appinfo['depots'][str(depotid)]['manifests']['public'])
                print("Archiving", appinfo['common']['name'], "depot", depotid, "manifest", manifest)
                exit_status += (0 if archive_manifest(try_load_manifest(appid, depotid, manifest, args.branch), c, name, args.dry_run, args.server, args.backup) else 1)
        else:
            print("Archiving all latest depots for", appinfo['common']['name'], "build", appinfo['depots']['branches']['public']['buildid'])
            for depot in appinfo["depots"]:
                if isinstance(depot, int) or (isinstance(depot, str) and depot.isdigit()):
                    get_depotkeys(appid, depot)
                else:
                    continue
                depotinfo = appinfo["depots"][depot]
                if not "manifests" in depotinfo or not "public" in depotinfo["manifests"]:
                    continue
                exit_status += (0 if archive_manifest(try_load_manifest(appid, depot, get_gid(depotinfo["manifests"]["public"])), c, depotinfo["name"] if "name" in depotinfo else "unknown", args.dry_run, args.server, args.backup) else 1)
    #steam_client.logout()
    exit(exit_status)
