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

X1 = str_to_point(m1.split(',')[0])
X2 = str_to_point(m1.split(',')[1])
X3 = Ni * X1
X4 = Ni * X2
hash_x4 = f"{X4.x()}{X4.y()}"
#b64_x4 = base64.b64encode(X4.to_bytes()).decode('utf-8')
hash_x4 = base64.b64encode(sha256(hash_x4.encode('utf-8')).digest()).decode('utf-8')
X5 = xor_strings(hash_x4.encode().hex(),idi.encode().hex())

#print(m1.split(','))
str_x3 = base64.b64encode(X3.to_bytes()).decode('utf-8')
_t = f"{m1.split(',')[0]}{m1.split(',')[1]}{str_x3}{idi}{idg}"
X6 = base64.b64encode(sha256(_t.encode('utf-8')).digest()).decode('utf-8')
m2 = f"{str_x3},{X5},{X6}"
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

hash_bitwise_x4 = f"{X4.x()}{X4.y()}"
hash_bitwise_x4 = ~int(hash_bitwise_x4)

SKig = base64.b64encode(sha256(str(hash_bitwise_x4).encode('utf-8')).digest()).decode('utf-8')

_hash = f"{SKig}{str_x3}{X5}{X6}"
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
