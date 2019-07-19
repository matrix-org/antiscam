# -*- coding: utf-8 -*-
# Copyright 2017, 2018 New Vector Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import sys
import yaml

from gevent.pywsgi import WSGIServer
import gevent

from bot.http import app
from bot.matrix import MatrixClient
import bot.settings

class BotHandler(object):
    def __init__(self, cli):
        self.cli = cli

    def on_room_event(self, roomid, ev):
        if ev['type'] != 'm.room.message':
            return
        if ev['content']['msgtype'] != 'm.text':
            return
        if ev['content']['body'].startswith('$'):
            self.process_command(roomid, ev['sender'], ev['content']['body'])

    def on_room_invite(self, roomid, room):
        self.cli.join_room(roomid)

    def process_command(self, roomid, userid, cmd):
        parts = cmd.split(' ')
        if parts[0] == '$url':
            self.handle_url(roomid, userid, parts[1:])
        elif parts[0] == '$mods':
            self.handle_mods(roomid, userid, parts[1:])

    def handle_url(self, roomid, userid, args):
        if len(args) < 1:
            cli.send_plaintext_notice(roomid, "url command requires arguments")
            return

        settings = bot.settings.get()

        admins = []
        if 'admins' in settings:
            admins = settings['admins']

        mods = []
        if 'mods' in settings:
            mods = settings['mods']

        if userid not in admins and userid not in mods:
            cli.send_plaintext_notice(roomid, "url command only usable by admin or mod")
            return
            
        whitelist = []
        if 'url_whitelist' in settings:
            whitelist = settings['url_whitelist']
        if args[0] == 'list':
            if not whitelist or len(whitelist) == 0:
                msg = "No URLs are whitelisted"
            else:
                msg = "URL whitelist: %s" % (','.join(whitelist),)
            cli.send_plaintext_notice(roomid, msg)
        elif args[0] == 'add':
            if len(args) < 2:
                cli.send_plaintext_notice(roomid, "$url add <url>")
                return
            if whitelist is None:
                whitelist = []
            whitelist.append(args[1].encode('utf8'))
            settings['url_whitelist'] = whitelist
            bot.settings.save()
            cli.send_plaintext_notice(roomid, "Added %s" % (args[1],))
        elif args[0] == 'remove':
            if len(args) < 2:
                cli.send_plaintext_notice(roomid, "$url remove <url>")
                return
            if whitelist is None or args[1] not in whitelist:
                cli.send_plaintext_notice(roomid, "domain not found in list")
            whitelist.remove(args[1])
            bot.settings.save()
            cli.send_plaintext_notice(roomid, "Removed %s" % (args[1],))

    def handle_mods(self, roomid, userid, args):
        if len(args) < 1:
            cli.send_plaintext_notice(roomid, "mods command requires arguments")
            return

        settings = bot.settings.get()

        admins = []
        if 'admins' in settings:
            admins = settings['admins']

        if userid not in admins:
            cli.send_plaintext_notice(roomid, "mods command only usable by admin")
            return

        mods = []
        if 'mods' in settings:
            mods = settings['mods']
        if args[0] == 'list':
            if not mods or len(mods) == 0:
                msg = "No moderators"
            else:
                msg = "moderators: %s" % (','.join(mods),)
            cli.send_plaintext_notice(roomid, msg)
        elif args[0] == 'add':
            if len(args) < 2:
                cli.send_plaintext_notice(roomid, "$mods add @user:example.com")
                return
            if mods is None:
                mods = []
            mods.append(args[1].encode('utf8'))
            settings['mods'] = mods
            bot.settings.save()
            cli.send_plaintext_notice(roomid, "%s is now a moderator" % (args[1],))
        if args[0] == 'remove':
            if len(args) < 2:
                cli.send_plaintext_notice(roomid, "$mods remove @user:example.com")
                return
            mods.remove(args[1])
            bot.settings.save()
            cli.send_plaintext_notice(roomid, "%s is no longer a moderator" % (args[1],))
            


logging.basicConfig()

private_settings = {}

try:
    with open('config/privsettings.yaml') as f:
        private_settings = yaml.load(f)
    tok = private_settings['token']
except:
    print("Failed to load token from privsettings.yaml")
    sys.exit(1)


http_server = WSGIServer(('localhost', 7000), app)
http_greenlet = gevent.spawn(http_server.serve_forever)

cli = MatrixClient('http://localhost:8008/', tok)
cli.handler = BotHandler(cli)
cli_greenlet = gevent.spawn(cli.run)

gevent.joinall([http_greenlet, cli_greenlet])

