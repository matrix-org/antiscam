from flask import Flask

import json

import bot.settings

app = Flask(__name__)

@app.route("/settings.json")
def settings():
    return json.dumps(bot.settings.get())
