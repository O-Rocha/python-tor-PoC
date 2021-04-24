import requests as req
import rsa #assimétrica
from cryptography.fernet import Fernet # simétrica

#variables
target_address = 'http://0.0.0.0:43001/Bob'
nodes_list = ['http://0.0.0.0:43000/server_1', 'http://0.0.0.0:43000/server_2', 'http://0.0.0.0:43000/server_3']

#Recupera public keys dos servers
with open('Servers/server1/pk-server_1.pem', 'rb') as server_1:
    key_data = server_1.read()
    server_1_pk = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)

with open('Servers/server2/pk-server_2.pem', 'rb') as server_2:
    key_data = server_2.read()
    server_2_pk = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)

with open('Servers/server3/pk-server_3.pem', 'rb') as server_3:
    key_data = server_3.read()
    server_3_pk = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)

with open('Bob/pk-bob.pem', 'rb') as bob:
    key_data = bob.read()
    bob_pk = rsa.PublicKey.load_pkcs1_openssl_pem(key_data)

#models
class TorPackage:
    def __init__(self, encrypted_cypher_key, next_node, message):
        self.encrypted_cypher_key = encrypted_cypher_key
        self.next_node = next_node       
        self.message = message
       
    def __str__(self):
        return "{key}, {next}, {message}".format(key=self.encrypted_cypher_key, next=self.next_node, message=self.message)

#auxiliary functions
def Wrap(public_key, next_node, mensagem):
    key = Fernet.generate_key()
    enc = Fernet(key)

    encrypted_cypher_key = rsa.encrypt(key, public_key).hex()

    next_node = enc.encrypt(next_node.encode('utf8')).decode('utf8')

    mensagem = enc.encrypt(mensagem.encode('utf8')).decode('utf8')

    tor_package = TorPackage(encrypted_cypher_key, next_node, mensagem)

    return tor_package

def make_request(url, tor_package):
    try:
        req.post(url, data={'tor_pack': str(tor_package)})
        return 0
    except:
        return -1

if __name__ == '__main__':
    bob_pack = Wrap(bob_pk, 'null', 'Teste')

    server3_pack = Wrap(server_3_pk, target_address, str(bob_pack))

    server2_pack = Wrap(server_2_pk, nodes_list[2], str(server3_pack))

    server1_pack = Wrap(server_1_pk, nodes_list[1], str(server2_pack))

    resp = make_request(nodes_list[0], server1_pack)

    print(resp)