#!/usr/bin/env python3
from argparse import ArgumentParser
from os import makedirs, listdir, path
from time import sleep

if __name__ == "__main__": # exit before we import our shit if the args are wrong
    parser = ArgumentParser(description='Download appinfo changes since the last time we downloaded any appinfo.')
    parser.add_argument("-i", help="Log into a Steam account interactively.", dest="interactive", action="store_true")
    parser.add_argument("-d", help="daemon mode: keep running in the background", dest="daemon", action="store_true")
    parser.add_argument("-n", help="no skip: always download appinfo, even if token is missing", dest="no_skip", action="store_true")
    parser.add_argument("-t", type=int, help="Number of seconds to sleep between requests in daemon mode (default 5)", dest="time", default=5)
    parser.add_argument("-u", type=str, help="Username for non-interactive login", dest="username", nargs="?")
    parser.add_argument("-p", type=str, help="Password for non-interactive login", dest="password", nargs="?")
    args = parser.parse_args()

from steam.client import SteamClient
from steam.core.msg import MsgProto
from steam.enums import EResult
from steam.enums.emsg import EMsg
from steam.webapi import WebAPI
from login import auto_login

if __name__ == "__main__":
    # Create directories
    makedirs("./appinfo", exist_ok=True)
    makedirs("./depots", exist_ok=True)

    steam_client = SteamClient()
    print("Connecting to the Steam network...")
    steam_client.connect()
    print("Logging in...")
    if args.interactive:
        auto_login(steam_client, fallback_anonymous=False)
    elif args.username:
        auto_login(steam_client, args.username, args.password)
    else:
        auto_login(steam_client)

    highest_changenumber = 0
    if path.exists("./last_change.txt"):
        with open("./last_change.txt", "r") as f:
            highest_changenumber = int(f.read())
    else:
        # if we haven't run get_appinfo yet, just find the last changenumber we downloaded
        for file in listdir("./appinfo"):
            if not file.endswith(".vdf"): continue
            changenumber = int(file.split("_")[1].replace(".vdf", ""))
            if changenumber > highest_changenumber:
                highest_changenumber = changenumber
    while True:
        msg = MsgProto(EMsg.ClientPICSChangesSinceRequest)
        msg.body.since_change_number = highest_changenumber
        msg.body.send_app_info_changes = True
        print("Asking Steam PICS for changes since %s..." % (highest_changenumber))
        response = steam_client.wait_event(steam_client.send_job(msg))[0].body
        if response.force_full_app_update:
            print("Your appinfo is too old to get changes. Please redownload by "
                "running get_appinfo.py.")
            exit(1)
        msg = MsgProto(EMsg.ClientPICSProductInfoRequest)
        print("Latest change:", response.current_change_number)
        if response.current_change_number != highest_changenumber:
            needed_tokens = []
            for change in response.app_changes:
                if change.needs_token:
                    needed_tokens.append(change.appid)
            tokens = steam_client.get_access_tokens(app_ids=needed_tokens)
            token_count = 0
            if tokens and 'apps' in tokens.items():
                for app, token in tokens['apps'].items():
                    if token != 0:
                        token_count += 1
            single = (token_count == 1)
            print("Got", "token" if single else "tokens", "for", token_count, "app" if single else "apps")
            for change in response.app_changes:
                if change.needs_token:
                    if change.appid in tokens['apps'].keys() and tokens['apps'][change.appid] != 0:
                        print("using token for app", change.appid)
                        app = msg.body.apps.add()
                        app.appid = change.appid
                        app.access_token = tokens['apps'][change.appid]
                    elif args.no_skip:
                        print("trying to download public_only appinfo for app", change.appid)
                        app = msg.body.apps.add()
                        app.appid = change.appid
                    else:
                        print("skipping app", change.appid, "(missing token)")
                else:
                    msg.body.apps.add().appid = change.appid
            for appinfo_response in steam_client.wait_event(steam_client.send_job(msg),
                    15)[0].body.apps:
                # Write vdf appinfo to disk
                appinfo_path = "./appinfo/%s_%s.vdf" % (appinfo_response.appid,
                        appinfo_response.change_number)
                if not path.exists(appinfo_path):
                    with open(appinfo_path, "wb") as f:
                        f.write(appinfo_response.buffer[:-1])
                        print("Saved appinfo for app", appinfo_response.appid,
                                "changenumber", appinfo_response.change_number)
        highest_changenumber = response.current_change_number
        with open("./last_change.txt", "w") as f:
            f.write(str(highest_changenumber))
        if args.daemon:
            sleep(args.time)
        else:
            break
