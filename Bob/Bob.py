from flask import Flask, request
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

def getPrivateKey(path):
    with open(path, 'rb') as reader:
        key_data = reader.read()
        sk = rsa.PrivateKey._load_pkcs1_pem(key_data)
    return sk

@app.route('/Bob',  methods= ['POST', 'GET'])
def Bob():
    print('bob foi chamado')
    try:
        if request.method == 'POST':
            tor_pack = decodeTorPack()
    except:
        print('erro no http Bob')

    server_sk = getPrivateKey('sk-bob.pem')
    cypher_key = rsa.decrypt(tor_pack.encrypted_cypher_key, server_sk)
    enc = Fernet(cypher_key)

    new_tor_pack = peel(tor_pack.message, enc)
    print('Mensagem enviada para Bob: {}'.format(new_tor_pack.message))

    return 'ok'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=43001, debug=True)

