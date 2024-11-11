#!/usr/bin/env python3
from argparse import ArgumentParser
from os import makedirs, path
from sys import argv

if __name__ == "__main__": # exit before we import our shit if the args are wrong
    parser = ArgumentParser(description='Download appinfo from Steam for one or '
            'more apps (or all of them).\n'
            "To get appinfo for hidden apps you'll need to log into an account "
            "that owns them.")
    parser.add_argument("-i", help="Log into a Steam account interactively.", dest="interactive", action="store_true")
    parser.add_argument("-u", type=str, help="Username for non-interactive login", dest="username", nargs="?")
    parser.add_argument("-p", type=str, help="Password for non-interactive login", dest="password", nargs="?")
    parser.add_argument('appids', metavar='appid', type=int, nargs='*', help='Apps '
            'to get appinfo for. If empty, will download appinfo for all '
            'publicly visible apps on Steam (this will take a while)!')
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
        auto_login(steam_client, fallback_anonymous=False, relogin=False)
    elif args.username:
        auto_login(steam_client, args.username, args.password)
    else:
        auto_login(steam_client)

    # Parse arguments
    appids = []
    if len(args.appids) > 0:
        appids = args.appids
    else:
        print("Fetching list of apps from WebAPI...")
        for app in WebAPI(None).ISteamApps.GetAppList_v2()['applist']['apps']:
            appids.append(app['appid'])
        # Write the current changenumber, for use later with update_appinfo
        with open("./last_change.txt", "w") as f:
            msg = MsgProto(EMsg.ClientPICSChangesSinceRequest)
            msg.body.since_change_number = 0
            response = steam_client.wait_event(steam_client.send_job(msg))[0].body
            print("Latest change:", response.current_change_number)
            f.write(str(response.current_change_number))

    # Get app access tokens
    print("Getting app access tokens...")
    tokens = steam_client.get_access_tokens(app_ids=appids)
    token_count = 0
    if tokens and 'apps' in tokens.items():
        for app, token in tokens['apps'].items():
            if token != 0:
                token_count += 1
    single = (token_count == 1)
    print("Got", "token" if single else "tokens", "for", token_count, "app" if single else "apps")

    # Fetch appinfo in groups of 30 (the maximum number of apps PICS will give
    # us in one message)
    for group in [appids[i:i + 30] for i in range(0, len(appids), 30)]:
        msg = MsgProto(EMsg.ClientPICSProductInfoRequest)
        for app in group:
            msg_app = msg.body.apps.add()
            msg_app.appid = app
            if app in tokens['apps']:
                msg_app.access_token = tokens['apps'][app]
        print("Asking Steam PICS for appinfo for %s %s..." % (len(msg.body.apps),
            "app" if len(msg.body.apps) == 1 else "apps"))
        while True:
            try:
                response = steam_client.wait_event(steam_client.send_job(msg), 15)[0].body
                break
            except TypeError:
                print("Timeout reached, retrying...")
        print("Received response from Steam PICS containing info for %s %s." %
            (len(response.apps), "app" if len(response.apps) == 1 else "apps"))
        for appinfo_response in response.apps:
            # Write vdf appinfo to disk
            appinfo_path = "./appinfo/%s_%s.vdf" % (appinfo_response.appid,
                    appinfo_response.change_number)
            with open(appinfo_path, "wb") as f:
                f.write(appinfo_response.buffer[:-1])
                print("Saved appinfo for app", appinfo_response.appid,
                        "changenumber", appinfo_response.change_number)
