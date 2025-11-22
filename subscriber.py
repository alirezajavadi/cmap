import os
import subprocess
import time
import base64
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey, VerifyingKey
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

HOME_DIR="/home/raspi/subscriber/"
CONFIG_DIR = f"{HOME_DIR}config/"

priv_hex = "60a435ba3424b6eb2eab533fd0ddf0acfafd35b2324cd97378849d4d23a6f661"
SKi = SigningKey.from_string(bytes.fromhex(priv_hex), curve=SECP256k1)
PKi = SKi.get_verifying_key()

PKg = VerifyingKey.from_string(bytes.fromhex("02467e307a469d0fadde5cd83d15f9b341ec229919fad7bf28bf249496f2b8c085"), curve=SECP256k1)

# send a hello and IDg
with open(f"{CONFIG_DIR}IDg","r") as f:
	idg = f.readline().replace("\n","")
hello_idg = f"Hello,{idg}"
print(f"\033[96m[+] Sending (Hello,IDg) : {{{hello_idg}}}\033[0m")
os.system(f"mosquitto_pub -h {mqtt_broker} -t {mqtt_topic} -p {mqtt_port} -m {hello_idg} > /dev/null")

# mqtt connection: receiving m1
try:
	command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -C 1"
	_temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
	m1 = _temp.stdout.decode("utf-8").replace("\n","")
	print(f"\033[92m[+] M1 has been received : {{{m1}}}\033[0m")
except Exception as e:
	print(e)
	exit()

with open(f"{CONFIG_DIR}IDi") as f:
	idi = f.readline().replace('\n','')

Ni = int.from_bytes(os.urandom(32), byteorder='big')

X1 = str_to_point(m1)
X2 = Ni * PKi.pubkey.point
X3 = SKi.privkey.secret_multiplier * X1
X4 = Ni * SKi.privkey.secret_multiplier * PKg.pubkey.point
hash_x4 = f"{X4.x()}{X4.y()}"
hash_x4 = base64.b64encode(sha256(hash_x4.encode('utf-8')).digest()).decode('utf-8')
X5 = xor_strings(hash_x4.encode().hex(),idi)

str_x3 = base64.b64encode(X3.to_bytes()).decode('utf-8')
str_x4 = base64.b64encode(X4.to_bytes()).decode('utf-8')
_t = f"{str_x3}{str_x4}{X5}{idi}{idg}"

X6 = base64.b64encode(sha256(_t.encode('utf-8')).digest()).decode('utf-8')
X2_toSend = base64.b64encode(X2.to_bytes()).decode('utf-8')
m2 = f"{X2_toSend},{X5},{X6}"
print(f"\033[96m[+] Sending M2 : {{{m2}}}\033[0m")
# send m2
os.system(f"mosquitto_pub -h {mqtt_broker} -t {mqtt_topic} -p {mqtt_port} -m {m2} > /dev/null")

# mqtt connection: receiving m3
try:
        command=f"mosquitto_sub -h {mqtt_broker} -p {mqtt_port} -t {mqtt_topic} -C 1"
        _temp = subprocess.run(command.split(" "), stdout=subprocess.PIPE)
        m3 = _temp.stdout.decode("utf-8").replace("\n","")
        print(f"\033[92m[+] M3 has been received : {{{m3}}}\033[0m")
except Exception as e:
        print("m3:",e)
        exit()

_x3 = f"{X3.x()}{X3.y()}"
_x4 = f"{X4.x()}{X4.y()}"
SKig = base64.b64encode(sha256(f"{_x3}{_x4}".encode('utf-8')).digest()).decode('utf-8')

_hash = f"{SKig}{X2_toSend}{X5}{X6}"
calculated_hash_m3 = base64.b64encode(sha256(_hash.encode('utf-8')).digest()).decode('utf-8')

if calculated_hash_m3 == m3:
	print("[+] Gateway has been authenticated successfully.")
	print(f"\033[1m[+] Session Key: {SKig}\033[0m")
else:
	print("[-] Wrong Credentials!")
	exit()

end = time.time()
elapsed_time = (end-start)*1000
print(f"---------------------------\nElapsed Time (millisec): {elapsed_time}")
with open("timing","a") as f:
        f.write(str(elapsed_time)+"\n")
