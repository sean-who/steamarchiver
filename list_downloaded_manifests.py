#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify
from datetime import datetime
from os import listdir
from os.path import exists
from vdf import loads

if __name__ == "__main__": # exit before we import our shit if the args are wrong
    parser = ArgumentParser(description='Print information about downloaded depots and manifests.\nSpecify either depots and/or manifests to print information on, or one or more apps to see whether their latest depots are downloaded.\nIf neither is specified, the script will print information on all downloaded depot manifests.')
    parser.add_argument('--all-apps', help="Act as if every appid in the appinfo folder was specified", dest="all_apps", action='store_true')
    parser.add_argument('--duplicate-appinfo', help="When used with --all-apps or -a, print info for old versions of appinfo instead of always using the latest change.", dest="duplicate_appinfo", action="store_true")
    parser.add_argument('--no-search-chunks', help="Don't verify all the chunks for a depot are downloaded, just verify the manifest itself is downloaded", dest="search_chunks", action="store_false")
    parser.add_argument('-a', type=int, help="Appid to print information about (can be used multiple times).", action='append', metavar="appid", dest="appid")
    parser.add_argument('-d', type=int, help="Depot to print information about (can be used multiple times). "
        "If not present, all downloaded depots will be used.", action='append', metavar="depotid", dest="depotid")
    parser.add_argument('-m', type=int, help="Manifest to print information about (can be used multiple times). "
        "If not present, all downloaded manifests will be used.", action='append', metavar="manifestid", dest="manifestid")
    args = parser.parse_args()

from steam.core.manifest import DepotManifest

def print_app_info(appid, duplicate_appinfo=False, search_chunks=True):
    changenumbers = []
    for appinfo_file in listdir("./appinfo/"):
        appinfo_file = appinfo_file.split("_")
        try:
            if int(appinfo_file[0]) == appid:
                changenumbers.append(int(appinfo_file[1].replace(".vdf", "")))
        except ValueError:
            pass
    if duplicate_appinfo:
        for change in changenumbers:
            with open("./appinfo/%s_%s.vdf" % (appid, change), "rb") as f:
                try:
                    appinfo = loads(f.read().decode("utf-8"))
                except UnicodeDecodeError:
                    f.seek(0)
                    appinfo = loads(f.read().decode("latin1"))
            if 'common' not in appinfo['appinfo'].keys():
                print("App %s change #%s (no common info)" % (appid, change))
            elif 'name' not in appinfo['appinfo']['common'].keys():
                print("App %s change #%s (no name)" % (appid, change))
            else:
                print("App %s change #%s: %s" % (appid, change, appinfo['appinfo']['common']['name']))
            print_branches(appinfo, search_chunks)
    else:
        try:
            highest_changenumber = next(reversed(sorted(changenumbers)))
        except StopIteration:
            print("No local appinfo for app", appid)
            return
        with open("./appinfo/%s_%s.vdf" % (appid, highest_changenumber), "rb") as f:
            try:
                appinfo = loads(f.read().decode("utf-8"))
            except UnicodeDecodeError:
                f.seek(0)
                appinfo = loads(f.read().decode("latin1"))
        if 'common' not in appinfo['appinfo'].keys():
            print("App %s change #%s (no common info)" % (appid, highest_changenumber))
        elif 'name' not in appinfo['appinfo']['common'].keys():
            print("App %s change #%s (no name)" % (appid, highest_changenumber))
        else:
            print("App %s change #%s: %s" % (appid, highest_changenumber, appinfo['appinfo']['common']['name']))
        print_branches(appinfo, search_chunks)

def print_all_app_info(duplicate_appinfo = False, search_chunks=True):
    apps = []
    for app in listdir("./appinfo"):
        try:
            app = int(app.split("_")[0])
        except ValueError:
            continue
        if app not in apps:
            apps.append(app)
    for app in apps:
        print_app_info(app, duplicate_appinfo, search_chunks)

def print_branches(appinfo, search_chunks=True):
    depots = []
    depot_branch_manifests = {}
    depot_names = {}
    depot_files = {}
    depots_downloaded = {}
    depots_in_branch = {}
    if 'depots' not in appinfo['appinfo'].keys():
        print("\t[App contains no depots.]")
        return
    if 'branches' not in appinfo['appinfo']['depots'].keys():
        print("\t[App contains no branches.]")
        return
    for depot, depot_info in appinfo['appinfo']['depots'].items():
        try:
            depot = int(depot)
            depots.append(depot)
        except ValueError:
            continue
        depot_names[depot] = depot_info['name'] if 'name' in depot_info.keys() else None
        depot_branch_manifests[depot] = {}
        try:
            for branch, manifest in depot_info['manifests'].items():
                depot_branch_manifests[depot][branch] = manifest
        except KeyError:
            pass
    for branch_name, branch_info in appinfo['appinfo']['depots']['branches'].items():
        depots_downloaded[branch_name] = 0
        depots_in_branch[branch_name] = len(depots)
        if 'buildid' not in branch_info.keys():
            print("\tBranch %s: no build" % branch_name, end="")
        elif 'timeupdated' not in branch_info.keys():
            print("\tBranch %s: build %s, last update unknown" % (branch_name, branch_info['buildid']), end="")
        else:
            print("\tBranch %s: build %s, last update %s" % (branch_name, branch_info['buildid'], datetime.fromtimestamp(int(branch_info['timeupdated']))), end="")
        if "pwdrequired" in branch_info.keys() and branch_info["pwdrequired"] == "1":
            found_other_branch = False
            for other_branch_name, other_branch_info in appinfo['appinfo']['depots']['branches'].items():
                if other_branch_name != branch_name and not 'pwdrequired' in other_branch_info.keys() and 'buildid' in other_branch_info.keys() and other_branch_info["buildid"] == branch_info["buildid"]:
                    found_other_branch = True
                    print(", even with %s" % other_branch_name, end="")
                    for depot in depot_branch_manifests:
                        if other_branch_name in depot_branch_manifests[depot]:
                            depot_branch_manifests[depot][branch_name] = depot_branch_manifests[depot][other_branch_name]
            if not found_other_branch:
                print("\n\t\t[No manifest information, this branch requires a password.]")
                continue
        print()
        for index, depot in enumerate(depots):
            if not depot in depot_files.keys():
                try:
                    depot_files[depot] = listdir("./depots/%s/" % depot)
                except FileNotFoundError:
                    print("\t\t[Missing depot " + str(depot) + ("(%s).]" % (depot_names[depot]) if depot_names[depot] else ".]"))
                    continue
            if branch_name in depot_branch_manifests[depot].keys():
                if print_depot_info(depot, depot_files[depot],
                        name=depot_names[depot],
                        manifests=[depot_branch_manifests[depot][branch_name]],
                        print_not_exists=True,
                        search_chunks=search_chunks):
                    depots_downloaded[branch_name] += 1
            else:
                if depot_names[depot]:
                    print("\t\t[Depot %s (%s) is not in this branch.]" % (depot, depot_names[depot]))
                else:
                    print("\t\t[Depot %s is not in this branch.]" % (depot))
                depots_in_branch[branch_name] -= 1
        print("\t\tDepots available: %s/%s" % (depots_downloaded[branch_name], depots_in_branch[branch_name]))
    if 'public' in appinfo['appinfo']['depots']['branches'].keys() and search_chunks:
        print("\t%s/%s depots for %s are up-to-date with the public branch" % (depots_downloaded["public"], len(depots), appinfo['appinfo']['common']['name']))

def print_depot_info(depotid, depot_files, manifests=None, print_not_exists=True, name=None, search_chunks=True):
    path = "./depots/%s/" % depotid
    if not exists(path):
        if name:
            print("\t\tDepot %s (%s) not found" % (depotid, name), end="")
        else:
            print("\t\tDepot %s not found" % depotid, end="")
        if manifests and len(manifests) == 1:
            print(" (should be manifest %s)" % manifests[0])
        else:
            print()
        return False
    if manifests:
        results = []
        for manifest in manifests:
            results.append(print_manifest_info(depotid, manifest, depot_files, print_not_exists, name, search_chunks))
        if all(x for x in results):
            return True
        else:
            return False
    else:
        try:
            results = []
            for file in listdir(path):
                if file.endswith(".zip"):
                    results.append(print_manifest_info(depotid, int(file.replace(".zip", "")), depot_files, print_not_exists, name, search_chunks))
            if all(x for x in results):
                return True
            else:
                return False
        except FileNotFoundError:
            if name:
                print("\t\tDepot %s (%s) not found" % (depotid, name))
            else:
                print("\t\tDepot %s not found" % depotid)
            return False

def print_manifest_info(depotid, manifestid, depot_files, print_not_exists=True, name=None, search_chunks=True):
    manifests = []
    manifest_zip = "./depots/%s/%s.zip" % (depotid, manifestid)
    chunks_on_disk = 0
    if not exists(manifest_zip):
        if print_not_exists:
            print("\t\tDepot", depotid, "manifest", manifestid, "not downloaded")
        return False
    with open(manifest_zip, "rb") as f:
        manifest = DepotManifest(f.read())
        manifests.append(manifest)
        if name:
            print("\t\tDepot", manifest.depot_id, "(%s) gid" % name, manifest.gid, "from", datetime.fromtimestamp(manifest.creation_time))
        else:
            print("\t\tDepot", manifest.depot_id, "gid", manifest.gid, "from", datetime.fromtimestamp(manifest.creation_time))
        if search_chunks:
            chunks_known = []
            chunks_on_disk = []
            for file in manifest.payload.mappings:
                for chunk in file.chunks:
                    chunkhex = hexlify(chunk.sha).decode()
                    if not chunkhex in chunks_known:
                        chunks_known.append(chunkhex)
                    if chunkhex in depot_files or (chunkhex + "_decrypted") in depot_files:
                        if not chunkhex in chunks_on_disk:
                            chunks_on_disk.append(chunkhex)
                    else:
                        print("\t\t\tchunk", chunkhex, "missing")
            print("\t\t\tchunks: %s/%s" % (len(chunks_on_disk), len(chunks_known)))
    return True

if __name__ == "__main__":
    if args.all_apps:
        print_all_app_info(args.duplicate_appinfo, args.search_chunks)
    elif args.appid:
        if args.depotid or args.manifestid:
            print("error: cannot specify appid and depot/manifestid at the same time")
            parser.print_help()
            exit(1)
        for app in args.appid:
            print_app_info(app, args.duplicate_appinfo, args.search_chunks)
    elif args.depotid:
        for depot in args.depotid:
            print_depot_info(depot, listdir("./depots/%s/" % depot), args.manifestid, search_chunks=args.search_chunks)
    else:
        for depot in sorted([int(x) for x in listdir("./depots/")]):
            print_depot_info(depot, listdir("./depots/%s/" % depot), args.manifestid, print_not_exists=False, search_chunks=args.search_chunks)
