# GDumper is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import argparse
import frida
import json
import os
import socket
import sys
import time


def parse_message(message, data):
    payload = message["payload"]
    arr = payload.split("::::")
    sess_file = None

    if mode == "dump":
        if arr[0] == "0":
            print("PK:" + arr[1])
            sess_file = open(path + "/pk" + ".bin", "w")
            sess_file.write(arr[1])
        elif arr[0] == "1":
            print("SK:" + arr[1])
            sess_file = open(path + "/sk" + ".bin", "w")
            sess_file.write(arr[1])
        elif arr[0] == "2":
            print("PKS:" + arr[1])
            sess_file = open(path + "/pks" + ".bin", "w")
            sess_file.write(arr[1])
        elif arr[0] == "3":
            msgId = int(arr[1][:4], 16)
            sess_file = open(path + "/" + str(int(round(time.time() * 1000))) + "_client_" + str(msgId) + ".bin", "w")
            sess_file.write(arr[1])
            print("[CLIENT] " + str(msgId))
        elif arr[0] == "4":
            msgId = int(arr[1][:4], 16)
            sess_file = open(path + "/" + str(int(round(time.time() * 1000))) + "_server_" + str(msgId) + ".bin", "w")
            sess_file.write(arr[1])
            print("[SERVER] " + str(msgId))
        if sess_file is not None:
            sess_file.close()
    elif mode == "proxy":
        msglen = len(payload)
        totalSent = 0
        while totalSent < msglen:
            sent = clientsocket.send(payload[totalSent:].encode())
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalSent = totalSent + sent
        if arr[0] == "0":
            print("PK:" + arr[1])
        elif arr[0] == "1":
            print("SK:" + arr[1])
        elif arr[0] == "2":
            print("PKS:" + arr[1])
        elif arr[0] == "3":
            msgId = int(arr[1][:4], 16)
            print("[CLIENT] " + str(msgId))
        elif arr[0] == "4":
            msgId = int(arr[1][:4], 16)
            print("[SERVER] " + str(msgId) + " " + str(totalSent))
        time.sleep(50.0 / 1000.0)


def get_table():
    with open('xptable.json') as data_file:
        return json.load(data_file)


def instrument_debugger_checks():
    injector = open("dumper.js", "r").read()

    if arch == "arm":
        cpuType = "1"
    else:
        cpuType = "0"

    gameType = ""

    if game == "bb":
        gameType = "0"
    elif game == "coc":
        gameType = "1"
    elif game == "cr":
        gameType = "2"

    xptable = get_table()[gameType][cpuType]
    xp1 = int(xptable["1"], 16)
    xp2 = int(xptable["2"], 16)
    xp3 = int(xptable["3"], 16)
    thumb = xptable["thumb"]
    if thumb:
        xp1 = xp1 + 1
        xp2 = xp2 + 1
        xp3 = xp3 + 1
    return injector.replace("xxp1", str(xp1)).replace("xxp2", str(xp2)).replace("xxp3", str(xp3))


def runCmd(cmd):
    os.system(cmd)


package_name = ""
path = ""

parser = argparse.ArgumentParser(description='Dump SC protocol data.')

parser.add_argument('-m', '--mode', help="Mode for dumper to run.", required=True)
parser.add_argument('-g', '--game', help="Game to run.", required=True)
parser.add_argument('-a', '--arch', help="Device architecture.", required=True)

args = parser.parse_args()

mode = args.mode
game = args.game
arch = args.arch

if mode != "proxy" and mode != "dump":
    print("Mode \"" + mode + "\" is not valid. Try \"proxy\" or \"dump\"")
    print("Proxy: Connects to the local node proxy server.")
    print("Dump: Starts a dump session.")
    sys.exit(1)

if game != "coc" and game != "bb" and game != "cr":
    print("Game \"" + game + "\" is not valid. Try \"coc\" - \"bb\" - \"cr\"")
    print("COC: Clash of Clans")
    print("BB: Boom Beach")
    sys.exit(1)

if arch != "arm" and arch != "x86":
    print("CPU Architecture \"" + arch + "\" is not valid. Try \"arm\" or \"x86\"")
    print("ARM: Recommended for most physical devices.")
    print("x86: Recommended for a few physical devices and most emulators.")
    sys.exit(1)

if game == "bb":
    package_name = "com.supercell.boombeach"
elif game == "coc":
    package_name = "com.supercell.clashofclans"
elif game == "cr":
    package_name = "com.supercell.clashroyale"

print("Starting dumper for " + package_name)

if not os.path.exists("dumps"):
    os.makedirs("dumps")

if mode == "proxy":
    print("Requesting connection to proxy.")
    clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientsocket.connect(('localhost', 10101))
elif mode == "dump":
    print("Preparing file dumps.")
    t = str(int(round(time.time() * 1000)))
    path = "dumps/" + package_name + "_" + t
    os.makedirs(path)

print("Killing " + package_name)
runCmd("adb shell am force-stop " + package_name)
print("Starting " + package_name)
runCmd("adb shell am start -n " + package_name + "/" + package_name + ".GameApp")

process = frida.get_usb_device().attach(package_name)
print("Frida attached.")
script = process.create_script(instrument_debugger_checks())
print("Dumper loaded.")
script.on('message', parse_message)
print("parse_message registered within script object.")
script.load()
sys.stdin.read()
