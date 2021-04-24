from flask import Flask, request
import requests as req
import rsa
from cryptography.fernet import Fernet

app = Flask(__name__)

#models
class TorPackage:
    def __init__(self, encrypted_cypher_key, next_node, message):
        self.encrypted_cypher_key = encrypted_cypher_key
        self.next_node = next_node       
        self.message = message
       
    def __str__(self):
        return "{key}, {next}, {message}".format(key=self.encrypted_cypher_key, next=self.next_node, message=self.message)

#auxiliary functions
def getPrivateKey(path):
    with open(path, 'rb') as reader:
        key_data = reader.read()
        sk = rsa.PrivateKey._load_pkcs1_pem(key_data)
    return sk

def peel(message, enc):
    new_message = enc.decrypt(bytes(message, 'utf8')).decode()

    try:
        new_infos = new_message.split(',')
    except:
        print('erro ao ler mensagem')
    finally:
        new_pack = None

    if len(new_infos) == 3:  
        new_infos = new_message.split(',')
        new_pack = TorPackage(new_infos[0], new_infos[1], new_infos[2])
    elif len(new_infos) != 3 and type(new_message) == str:
        new_pack = TorPackage('', '', new_message)
    
    return new_pack

def make_request(url, tor_package):
    try:
        req.post(url, data={'tor_pack': str(tor_package)})
        return 0
    except:
        return -1

def decodeTorPack():
    try:
        last_node = request.form['tor_pack']
        last_node = str(last_node).split(',')
    except:
        print('erro ao ler dados do nó anterior')
    
    if len(last_node) == 3:
        encrypted_cypher_key = bytes.fromhex(last_node[0])

        if last_node == 'null':
            next_node = None
        else:
            next_node = last_node[1]

        message = last_node[2]
        return TorPackage(encrypted_cypher_key, next_node, message)
    else:
        return None

#routes
@app.route('/server_1', methods= ['POST', 'GET'])
def server_one():
    print("server 1 foi chamado:")
    try:
        if request.method == 'POST':
            tor_pack = decodeTorPack()
    except:
        print('erro no http serve 1')

    if tor_pack is not None:
        server_sk = getPrivateKey('server1/sk-server_1.pem')
        cypher_key = rsa.decrypt(tor_pack.encrypted_cypher_key, server_sk)

        enc = Fernet(cypher_key)
        tor_pack.next_node = enc.decrypt(tor_pack.next_node.encode('utf8')).decode('utf8')
        
        new_tor_pack = peel(tor_pack.message, enc)

        print('informações do próximo nó')
        print(new_tor_pack)

        if tor_pack.next_node is not None:
            make_request(tor_pack.next_node , new_tor_pack)
        else:
            print(new_tor_pack.message)

        return 'ok'

@app.route('/server_2', methods= ['POST', 'GET'])
def server_two():
    print('server 2 foi chamado')
    try:
        if request.method == 'POST':
            tor_pack = decodeTorPack()
    except:
        print('erro no http serve 2')

    if tor_pack is not None:
        server_sk = getPrivateKey('server2/sk-server_2.pem')
        cypher_key = rsa.decrypt(tor_pack.encrypted_cypher_key, server_sk)
        
        enc = Fernet(cypher_key)
        tor_pack.next_node = enc.decrypt(tor_pack.next_node.encode('utf8')).decode('utf8')
        
        new_tor_pack = peel(tor_pack.message, enc)

        print('informações do próximo nó')
        print(new_tor_pack)

        if tor_pack.next_node is not None:
            make_request(tor_pack.next_node , new_tor_pack)
        else:
            print(new_tor_pack.message)

        return 'ok'

@app.route('/server_3', methods= ['POST', 'GET'])
def server_three():
    print('server 3 foi chamado')
    try:
        if request.method == 'POST':
            tor_pack = decodeTorPack()
    except:
        print('erro no http serve 1')

    if tor_pack is not None:
        server_sk = getPrivateKey('server3/sk-server_3.pem')

        cypher_key = rsa.decrypt(tor_pack.encrypted_cypher_key, server_sk)
        
        enc = Fernet(cypher_key)
        tor_pack.next_node = enc.decrypt(tor_pack.next_node.encode('utf8')).decode('utf8')
        
        new_tor_pack = peel(tor_pack.message, enc)

        print('informações do próximo nó')
        print(new_tor_pack)

        if tor_pack.next_node is not None:
            make_request(tor_pack.next_node , new_tor_pack)
        else:
            print(new_tor_pack.message)

        return 'ok'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=43000, debug=True)