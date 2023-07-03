import sys
import ipaddress
import naas

#sys.path.insert(0, "..")

n_connections = 1
swanctl_conf_path = "/etc/swanctl/conf.d/swanctl.conf"

s ='''connections {
    gw-gw {
        local_addrs  = 192.168.31.13
        remote_addrs = 192.168.31.11
        local {
            auth = psk
            id = keyid:12
        }
        remote {
            auth = psk
        }
        children {'''

with open(swanctl_conf_path, 'w') as f:
    f.write(s)

    lts = ipaddress.IPv4Address('48.0.0.0')
    rts = ipaddress.IPv4Address('16.0.0.0')

    for i in range(0, n_connections):
        s = '''
            net-net-%d {
                local_ts  = %s/24
                remote_ts = %s/24
                esp_proposals = aes128gcm128-x25519
            }''' % (i + 1, lts, rts)
        lts += 256
        rts += 256

        f.write(s)

    s = '''
        }
        version = 2
        reauth_time = 10800
        proposals = aes128-sha256-x25519
    }
}
secrets {
    ike-1 {
        secret = 0sv+NkxY9LLZvwj4qCC2o/gGrWDF2d21jL
    }
}'''
    f.write(s)

naas.system("swanctl --load-all")

for i in range(0, n_connections):
    out, err = naas.system("swanctl -i -c net-net-%d" % (i + 1))
    if (i + 1) % 100 == 0:
        print("%d tunnels" % (i + 1))

#    print(out)
