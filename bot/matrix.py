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

import urllib
import logging
import ujson as json
import time
import random
import string

import grequests
import gevent

logger = logging.getLogger(__name__)


def makeTxnid():
    return "%d%s" % (
        time.time() * 1000,
        ''.join([random.choice(string.ascii_lowercase) for _ in xrange(5)])
    )


class MatrixClient(object):
    def __init__(self, base_url, access_token):
        self.base_url = base_url
        self.access_token = access_token
        self.next_batch = None
        self.handler = None

    def send_event(self, roomid, event_type, ev):
        url = self.base_url + (
            '_matrix/client/r0/rooms/%s/send/%s/%s?access_token=%s' % (
                roomid, event_type, makeTxnid(), self.access_token,
            )
        )
        req = grequests.put(url, json=ev)
        req.send()
        if req.response is None:
            raise Exception("Request failed")
        elif req.response.status_code / 100 != 2:
            raise Exception("Request failed with code %r" % req.response.status_code)
        else:
            return True

    def send_plaintext_message(self, roomid, text):
        return self.send_event(roomid, 'm.room.message', {
            'msgtype': 'm.text',
            'body': text,
        })

    def send_plaintext_notice(self, roomid, text):
        return self.send_event(roomid, 'm.room.message', {
            'msgtype': 'm.notice',
            'body': text,
        })

    def join_room(self, roomid):
        url = self.base_url + (
            '_matrix/client/r0/join/%s?access_token=%s' % (
                roomid, self.access_token,
            )
        )
        req = grequests.post(url, json={})
        req.send()
        if req.response is None:
            raise Exception("Request failed")
        elif req.response.status_code / 100 != 2:
            raise Exception("Request failed with code %r" % req.response.status_code)
        else:
            return True

    def run(self):
        while True:
            try:
                sync = self.sync()
                self.process_sync(sync)
            except Exception as e:
                logger.warn("sync failed: %r", e)
                gevent.sleep(5)

    def sync(self):
        url = self.base_url + '_matrix/client/r0/sync'
        if self.next_batch is not None:
            print("syncing")
            url += '?since='+self.next_batch+'&timeout=30000'
        else:
            print("initial syncing")
            url += '?filter=' + json.dumps({
                'room': {
                    'timeline': {
                        'limit': 0,
                    }
                }
            })
        url += '&access_token='+self.access_token
        req = grequests.get(url)
        req.send()
        if self.next_batch is None:
            print("done!")

        if req.response is None:
            raise Exception("sync request failed: response was None")
        elif req.response.status_code / 100 != 2:
            logger.warn("sync request returned %r", req.response.text)
            raise Exception("sync request failed: status code %r", req.response.status_code)
        else:
            data = json.loads(req.response.text)
            self.next_batch = data['next_batch']
            return data

    def process_sync(self, sync):
        for roomid, room in sync['rooms']['join'].iteritems():
            for ev in room['timeline']['events']:
                self.handler.on_room_event(roomid, ev)
        for roomid, room in sync['rooms']['invite'].iteritems():
                self.handler.on_room_invite(roomid, room)

