import os
import subprocess
import time
import base64
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey
from ecdsa.ellipticcurve import Point, PointJacobi

def xor_strings(hex_str1, hex_str2):
        num1 = int(hex_str1, 16)
        num2 = int(hex_str2, 16)

        xor_result = num1 ^ num2

        return format(xor_result, 'x')

def str_to_point(b64_str):
        point = Point.from_bytes(SECP256k1.curve, base64.b64decode(b64_str.encode('utf-8')))
        return PointJacobi(SECP256k1.curve, point.x(), point.y(),1)

# timing
start = time.time()

# consts
mqtt_broker="192.168.100.100"
mqtt_port="1883"
mqtt_topic = "/auth"

HOME_DIR="/home/raspi/mqtt_tasks/ieee_medical_mqtt/protocol/"
CONFIG_DIR = f"{HOME_DIR}config/"



# mqtt connection: receiving a hello and IDg
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -C 1"
	_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	hello_idg = _temp.stdout.decode("utf-8").replace("\n","")
	print(f"\033[92m[+] (Hello,IDg) has been received : {{{hello_idg}}}\033[0m")
except Exception as e:
	print(e)
	exit()

idg = hello_idg.split(',')[1]


SKg = SigningKey.generate(curve=SECP256k1)
PKg = SKg.get_verifying_key()

Ng = int.from_bytes(os.urandom(32), byteorder='big')

curve = SECP256k1
P = curve.generator


X1 = Ng * P
X2 = Ng * PKg.pubkey.point

X1_toSend = base64.b64encode(X1.to_bytes()).decode('utf-8')
X2_toSend = base64.b64encode(X2.to_bytes()).decode('utf-8')

m1 = f"{X1_toSend},{X2_toSend}"
print(f"\033[96m[+] Sending M1 : {{{m1}}}\033[0m")
os.system(f"mosquitto_pub -h {mqtt_broker} -t {mqtt_topic} -p {mqtt_port} -m {m1} > /dev/null")


# mqtt connection: receiving m2
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -C 1"
	_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	m2 = _temp.stdout.decode("utf-8").replace("\n","")
	print(f"\033[92m[+] M2 has been received : {{{m2}}}\033[0m")
except Exception as e:
	print("m2:",e)
	exit()

m2 = m2.split(',')
b64_x3 = m2[0]
hex_x5 = m2[1]
b64_x6= m2[2]

_idi = (SKg.privkey.secret_multiplier * str_to_point(b64_x3))
_idi = f"{_idi.x()}{_idi.y()}"
_idi = base64.b64encode(sha256(_idi.encode('utf-8')).digest()).decode('utf-8')
_idi = xor_strings(_idi.encode().hex(),hex_x5)
idi = ''.join([chr(int(_idi[i:i+2], 16)) for i in range(0, len(_idi), 2)])

# authenticate
hash_value = f"{X1_toSend}{X2_toSend}{b64_x3}{idi}{idg}"
hash_value = base64.b64encode(sha256(hash_value.encode('utf-8')).digest()).decode('utf-8')
if b64_x6 == hash_value:
	print("[+] Subscriber has been authenticated successfully.")
else:
	print("[-] Wrong Credentials!")
	exit()


X4 = SKg.privkey.secret_multiplier * str_to_point(b64_x3)
hash_bitwise_x4 = f"{X4.x()}{X4.y()}"
hash_bitwise_x4 = ~int(hash_bitwise_x4)

SKig = base64.b64encode(sha256(str(hash_bitwise_x4).encode('utf-8')).digest()).decode('utf-8')

print(f"\033[1m[+] Session Key: {SKig}\033[0m")

_hash = f"{SKig}{m2[0]}{m2[1]}{m2[2]}"

m3 = base64.b64encode(sha256(_hash.encode('utf-8')).digest()).decode('utf-8')
# send m3
print(f"\033[96m[+] Sending M3 : {{{m3}}}\033[0m")
os.system(f"mosquitto_pub -h {mqtt_broker} -t {mqtt_topic} -p {mqtt_port} -m {m3} > /dev/null")


