#!/usr/bin/env python3
from argparse import ArgumentParser
from binascii import hexlify
from steam.client import SteamClient
from steam.core.msg import MsgProto
from steam.enums.emsg import EMsg
from os.path import exists
from sys import argv
from vdf import loads
from login import auto_login

if __name__ == "__main__":
    parser = ArgumentParser(description='Request and save depot keys.')
    parser.add_argument('-d', dest="depots", help="depot to get key for (can be used multiple times)", action="append", nargs='?', type=int)
    parser.add_argument('-a', dest="apps", help="app to get all depot keys for (can be used multiple times)", action="append", nargs='?', type=int)
    parser.add_argument("-i", help="Log into a Steam account interactively.", dest="interactive", action="store_true")
    parser.add_argument("-u", type=str, help="Username for non-interactive login", dest="username", nargs="?")
    parser.add_argument("-p", type=str, help="Password for non-interactive login", dest="password", nargs="?")
    args = parser.parse_args()
    steam_client = SteamClient()
    print("Connecting to the Steam network...")
    steam_client.connect()
    print("Logging in...")
    if args.interactive:
        auto_login(steam_client, fallback_anonymous=False, relogin=False)
    elif args.username:
        auto_login(steam_client, args.username, args.password)
    else:
        auto_login(steam_client)
    licensed_packages = []
    licensed_apps = []
    licensed_depots = []
    if not steam_client.licenses:
        licensed_packages = [17906] # if we don't have a license list, we're an anonymous account
    else:
        for license in steam_client.licenses.values():
            print("Found license for package %s" % license.package_id)
            licensed_packages.append(license.package_id)
    product_info = steam_client.get_product_info(packages=licensed_packages)
    for package in product_info['packages'].values():
        for depot in package['depotids'].values():
            print("Found license for depot %s" % depot)
            licensed_depots.append(depot)
        for app in package['appids'].values():
            print("Found license for app %s" % app)
            licensed_apps.append(app)

    if args.apps:
        diff = set(args.apps).difference(licensed_apps)
        if diff:
            result, granted_appids, granted_packageids = steam_client.request_free_license(diff)
            for package in granted_packageids:
                print("Obtained free license for package", package)
            for app in granted_appids:
                print("Obtained free license for app", app)
            licensed_apps += granted_appids
            licensed_packages += granted_packageids
            grant_diff = set(args.apps).difference(granted_appids)
            if grant_diff:
                if len(args.apps) == 1:
                    print("ERROR: unable to obtain license for", args.apps[0])
                else:
                    print("ERROR: unable to obtain licenses for", grant_diff)
                exit(1)
            else:
                # we got new licenses, so now we need to get the list of depots included in those licenses
                product_info = steam_client.get_product_info(packages=granted_packageids)
                if product_info:
                    for package in product_info['packages'].values():
                        for depot in package['depotids'].values():
                            print("Found license for depot %s" % depot)
                            licensed_depots.append(depot)

    msg = MsgProto(EMsg.ClientPICSProductInfoRequest)
    tokens = steam_client.get_access_tokens(app_ids=licensed_apps)
    for app in licensed_apps:
        body_app = msg.body.apps.add()
        body_app.appid = app
        if 'apps' in tokens.keys() and app in tokens['apps'].keys():
            body_app.access_token = tokens['apps'][app]
    job = steam_client.send_job(msg)
    appinfo_response = []
    response = steam_client.wait_event(job)[0].body
    for app in response.apps:
        appinfo_response.append(app)
    while response.response_pending:
        response = steam_client.wait_event(job)[0].body
        for app in response.apps:
            appinfo_response.append(app)
    app_dict = {}
    for app in appinfo_response:
        appinfo_path = "./appinfo/%s_%s.vdf" % (app.appid, app.change_number)
        app_dict[app.appid] = loads(app.buffer[:-1].decode('utf-8', 'replace'))['appinfo']
        if not exists(appinfo_path):
            with open(appinfo_path, "wb") as f:
                f.write(app.buffer[:-1])
            try:
                print("Saved appinfo for app", app.appid, "changenumber", app.change_number, app_dict[app.appid]['common']['name'])
            except KeyError:
                print("Saved appinfo for app", app.appid, "changenumber", app.change_number)

    keys_saved = []
    if exists("./depot_keys.txt"):
        with open("./depot_keys.txt", "r", encoding="utf-8") as f:
            for line in f.read().split("\n"):
                try:
                    keys_saved.append(int((line.split("\t")[0])))
                except ValueError:
                    continue
        print("%s keys already saved in depot_keys.txt" % len(keys_saved))
    with open("./depot_keys.txt", "a", encoding="utf-8", newline="\n") as f:
        for app, app_info in app_dict.items():
            if not app in licensed_apps:
                continue
            if args.apps:
                if app not in args.apps:
                    continue
            if not 'depots' in app_info:
                continue
            if not app in app_info['depots']:
                app_info['depots'][app] = {'name': app_info['common']['name']}
            for depot, info in app_info['depots'].items():
                try:
                    depot = int(depot)
                except ValueError:
                    continue
                if args.depots:
                    if depot not in args.depots:
                        continue
                if depot in keys_saved:
                    print("skipping previously saved key for depot", depot)
                    continue
                if (depot in licensed_depots) or (depot in licensed_apps):
                    try:
                        key = steam_client.get_depot_key(app, depot).depot_encryption_key
                    except AttributeError:
                        print("error getting key for depot", depot)
                        continue
                    else:
                        keys_saved.append(depot)
                        if key != b'':
                            key_hex = hexlify(key).decode()
                            if 'name' in info.keys():
                                f.write("%s\t\t%s\t%s" % (depot, key_hex, info['name']) + "\n")
                                print("%s\t\t%s\t%s" % (depot, key_hex, info['name']))
                            else:
                                f.write("%s\t\t%s" % (depot, key_hex) + "\n")
                                print("%s\t\t%s" % (depot, key_hex))
