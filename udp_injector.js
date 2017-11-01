const xp1 = 0x3243FC; // udp connection
const xp2 = 0x323AFC; // udp send message (first one)
const xp3 = 0x323A20; // udp pre-send (all)
const xp4 = 0x33C2F6; // possible rc4

const xp5 = 0x324980; // udp send 1 (subsequent packet)
const xp6 = 0x3248C0; // udp send 2 (used only on first packed)

function ba2hex(bufArray) {
    var uint8arr = new Uint8Array(bufArray);
    if (!uint8arr) {
        return '';
    }

    var hexStr = '';
    for (var i = 0; i < uint8arr.length; i++) {
        var hex = (uint8arr[i] & 0xff).toString(16);
        hex = (hex.length === 1) ? '0' + hex : hex;
        hexStr += hex;
    }

    return hexStr.toUpperCase();
}

function packetize(payload) {
    var packet = {
        sessionKey: payload.substring(0, 20),
        tickUpdate: null,
        contentMessage: null
    };
    payload = payload.substring(20);
    while (payload.length !== 0) {
        if (packet.tickUpdate === null) {
            var tickUpdate = parseInt(payload.substring(0, 2));
            packet.tickUpdate = {};
            payload = subs(payload, 2);
            if (tickUpdate > 0) {
                packet.tickUpdate.tick = parseInt("0x" + payload.substring(0, 2));
                payload = subs(payload, 2);
            }
        } else if (packet.contentMessage === null) {
            var msg = parseInt(payload.substring(0, 2));
            packet.contentMessage = {};
            payload = subs(payload, 2);
            if (msg > 0) {
                packet.contentMessage.tick = parseInt("0x" + payload.substring(0, 2));
                payload = subs(payload, 2);

                packet.contentMessage.msgId = parseInt("0x" + payload.substring(0, 4));
                payload = subs(payload, 4);

                if (payload.length > 0) {
                    msg = parseInt(payload.substring(0, 2));
                    payload = subs(payload, 2);
                    if (msg > 0) {
                        var encMsgLen = parseInt("0x" + payload.substring(0, 2));
                        payload = subs(payload, 2);
                        packet.contentMessage.encryptedPayload =
                            payload.substring(0, encMsgLen * 2);
                        payload = subs(payload, encMsgLen * 2);
                    }
                }
            }
        } else {
            packet.extraBytes = payload;
            payload = subs(payload, payload.length);
        }
    }

    console.log(JSON.stringify(packet));
}

function subs(str, start) {
    return str.substring(start);
}

function inject() {
    Process.enumerateModules({
        onMatch: function (module) {
            if (module.name === "libg.so") {
                var base = module.base;
                var pt1 = ptr(parseInt(base) + 1 + xp5);
                var pt2 = ptr(parseInt(base) + 1 + xp6);

                var sessionId = null;

                Interceptor.attach(pt1, {
                    onEnter: function (args) {
                        console.log("UDP SEND 1");
                        var p = ba2hex(Memory.readByteArray(ptr(parseInt(args[0]) + 1410), 64));
                        console.log(p);
                    },
                    onLeave: function (retval) {
                    }
                });
                Interceptor.attach(pt2, {
                    onEnter: function (args) {
                        console.log("UDP SEND 2");
                        var p = ba2hex(Memory.readByteArray(ptr(parseInt(args[0]) + 1410), 64));
                        if (sessionId === null) {
                            sessionId = p.substring(0, 10);
                        }
                        console.log(p);
                    },
                    onLeave: function (retval) {
                    }
                });
                Interceptor.attach(Module.findExportByName("libg.so", "sendto"), {
                    onEnter: function (args) {
                        if (sessionId !== null) {
                            var p = ba2hex(Memory.readByteArray(args[1], parseInt(args[2])));
                            if (p.startsWith(sessionId)) {
                                console.log("SENDTO");
                                packetize(p);
                            }
                        }
                    },
                    onLeave: function (retval) {
                    }
                });
            }
        },
        onComplete: function () {
        }
    });
}

inject();
