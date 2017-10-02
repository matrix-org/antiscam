# -*- coding: utf-8 -*-
# Copyright 2017 New Vector Ltd
#
# Portions taken from https://github.com/PhABC/antiScamBot_slack
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

import re
import logging
import ujson as json

from twisted.internet import reactor, defer
from twisted.web.client import Agent, readBody

logger = logging.getLogger(__name__)

class AntiScamSpamChecker(object):
    def __init__(self, config):
        self.eth_prog = re.compile(r'((0x)?[0-9a-fA-F]{40})')
        self.eth_priv = re.compile(r'([0-9a-fA-F]{64})')
        self.btc_prog = re.compile(r'([13][a-km-zA-HJ-NP-Z1-9]{25,34})')

        self.agent = Agent(reactor)

        self.settings = {}
        self.settings['url_whitelist'] = ['github.com','reddit.com','etherscan.io','myetherwallet.com',
                                          '0xproject.com','numer.ai','twitter.com','slack.com',
                                          'medium.com', 'ethplorer.io', 'metamask.io', 'steemit.com', 
                                          'youtube.com','hackingdistributed.com','ens.domains','bittrex.com',
                                          'consensys.net','forbes.com','coinmarketcap.com','liqui.io',
                                          'hitbtc.com']
        self.settings.update(config)

        reactor.callWhenRunning(self.update_settings)

    @defer.inlineCallbacks
    def update_settings(self):
        url = None
        try:
            url = self.settings['bot_urlbase'] + 'settings.json'
        except:
            logger.error("No 'bot_urlbase' specified: can't update settings")

        try:
            logger.debug("updating settings from %s", url)
            response = yield self.agent.request(
                'GET', url, None, None,
            )
            body = yield readBody(response)
            settings = json.loads(body)
            logger.debug("got new settings: %r", settings)
            self.settings.update(settings)
        except Exception as e:
            logger.error("Failed to update settings: %r", e)
        finally:
            reactor.callLater(60, self.update_settings)

    @staticmethod
    def parse_config(config):
        return config
    
    def check_event_for_spam(self, event):
        if not hasattr(event, "content") or "body" not in event.content:
            return False

        if self.isAdmin(event.sender) or self.isMod(event.sender):
            return False

        if self.isETH_BTC(event):
            return True
        elif self.isBadURL(event):
            return True

        return False

    def isAdmin(self, userId):
        if 'admin' not in self.settings:
            print("no admin setting")
            return False
        print("admin is %r" % (self.settings['admin'],))
        return userId == self.settings['admin']

    def isMod(self, userid):
        if 'mods' not in self.settings:
            return False

        mods = self.settings['mods']
        if mods is None:
            mods = []

        return userid in mods

    def isETH_BTC(self, event):
        'Detect events that contain ETH/BTC addresses'

        #Name of user
        #userinfo = self.scBot.api_call('users.info', user=data['user'])
        #username = userinfo['user']['name']
        #userID   = self.UserNameID_mapping[username]

        #Delete anything that remotely looks like an eth or btc address, except etherscan.
        eth_result = self.eth_prog.search(event.content['body'])
        btc_result = self.btc_prog.search(event.content['body'])

        #ETH privatekey
        eth_result_pv = self.eth_priv.search(event.content['body'])

        #Allow if etherscan address
        if 'etherscan.io/' in event.content['body']:
            logger.debug('%r: Etherscan address', event.event_id)
            return False

        #ETH address detection
        if eth_result_pv and eth_result_pv.group(1):
            logger.debug('%r: ETH private key detected.', event.event_id)

            #Send welcoming message
            #contactChan = self.scBot.api_call('im.open', user = userID)['channel']['id']

            #Message to user
            #msg = [ 'Hello,\n\n You posted a message containing a private key and the '  +
            #        'message was automatically deleted for your safety. *Never share  '  +
            #        'your private key with anyone, a malicious user could steal your '   +
            #        'coins/tokens.* No team member would ever ass you this.\n\n Please be vigilant.'+
            #        '\n\n The deleted message was the following : \n\n>>>{}'.format(data['text'])]

            #Sending warning message to user
            #self.postMessage(data, msg[0], chan = contactChan)
            
            #Deleting message
            #self.delete(data)

            return True
        #ETH address detection
        elif eth_result and eth_result.group(1):
            logger.debug('%r: ETH address detected.', event.event_id)

            #Send welcoming message
            #contactChan = self.scBot.api_call('im.open', user = userID)['channel']['id']

            #Message to post in channel
            #msg  = ['You posted an ETH address and ' + 
            #        'the message was deleted. We do this to ensure '   +
            #        'users security. Multiple offenses could lead  '   +
            #        'to account deactivation if deemed malicious.\n\n' +
            #         'The deleted message was the following : \n\n>>>{}'.format(data['text']) ]

            #Sending warning message to user
            #self.postMessage(data, msg[0], chan = contactChan)

            #Deleting message
            #self.delete(data)
            return True

        #BTC address detection
        if btc_result and btc_result.group(1):
            logger.debug('%r: BTC address detected.', event.event_id)

            #Send welcoming message
            #contactChan = self.scBot.api_call('im.open', user = userID)['channel']['id']

            #Message to post in channel
            #msg  = ['You posted a BTC address and ' + 
            #        'the message was deleted. We do this to ensure ' +
            #        'users security. Multiple offenses could lead  ' +
            #        'to account deactivation if deemed malicious.\n\n' +
            #         'The deleted message was the following : \n\n>>>{}'.format(data['text']) ]

            #Sending warning message to user
            #self.postMessage(data, msg[0], chan = contactChan)   

            #Deleting message
            #self.delete(data)
            return True

        return False

    def isBadURL(self, event):
        # Regex for URLs taken from PhABC/antiScamBot_slack
        #REGEX expression
        regex = r"(?:[-a-zA-Z0-9@:%_\+~.#=]{2,256}\.)?([-a-zA-Z0-9@:%_\+~#=]*\.[a-z]{2,12})\b(?:[-a-zA-Z0-9@:%_\+.~#?&\/\/=]*)"

        #Regular expression for URLs
        urls = re.findall(regex, event.content['body'])

        #If URL is found
        for domain in urls:
            #URL log
            logger.debug('%r: URL detected at {}'.format(domain), event.event_id)

            #If domain is not in whitelist
            if not domain in self.settings['url_whitelist']:

                #Channel with new moderator
                #contactChan = self.scBot.api_call('im.open', user = userID)['channel']['id']

                #Message to user
                #msg = [ 'Hello,\n\n You posted a message containing a non-approved domain ' +
                #        '({}). Please contact an admin or moderator to add '.format(domain) +
                #        'this domain to the URL whitelist if you consider it to be safe.\n' +
                #        '\nYou can see the whitelisted domains by typing `$url list`.\n\n'  +
                #        'The deleted message was the following : \n\n>>>{}'.format(data['text']) ]

                #Sending warning message to user
                #self.postMessage(data, msg[0], chan = contactChan)
                
                #Deleting message
                #self.delete(data)

                return True

        return False
