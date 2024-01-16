#!/usr/bin/env python3
# 实现wireguard客户端创建便携工具
import os, sys, getopt


def gen_key():
    os.system("wg genkey | tee privatekey | wg pubkey > publickey")

    with open("privatekey", "r") as f:
        privatekey = f.read()
    f.close()

    with open("publickey", "r") as f:
        publickey = f.read()
    f.close()

    os.remove(privatekey)
    os.remove(publickey)

    return {
        "publickey": publickey,
        "privatekey": privatekey,
    }


def gen_file(name, interface, peer, pubkey, priv_key):
    if not os.path.isdir(name):
        os.mkdir(name)

    with open(interface, "r") as f:
        s = f.read()
    f.close()

    s.replace("${PrivateKey}", priv_key)

    fdst = open("%s/%s.conf" % (name, name,), "w")
    fdst.write(s)
    fdst.close()

    with open(peer, "r") as f:
        s = f.read()
    f.close()

    s.replace("${PublicKey}", pubkey)
    fdst = open("%s/peer.conf" % name, "w")
    fdst.write(s)
    fdst.close()


def main():
    helper = """
    name --interface=local_template_file --peer=peer_template_file
    """
    if len(sys.argv) < 3: return

    name = sys.argv[1]

    try:
        opts, args = getopt.getopt(sys.argv[2:], "",
                                   ["interface=", "peer="])
    except getopt.GetoptError:
        print(helper)
        return

    interface = ""
    peer = ""

    for k, v in opts:
        if k == "--interface":
            interface = v
        if k == "--peer":
            peer = v
        ''''''
    if not interface or not peer:
        print(helper)
        return

    if not os.path.isfile(interface):
        print("ERROR:not found interface template %s" % interface)
        return
    if not os.path.isfile(peer):
        print("ERROR:not found peer template %s" % peer)
        return

    keys = gen_key()
    gen_file(name, interface, peer, keys["publickey"], keys["privatekey"])


if __name__ == "__main__": main()
