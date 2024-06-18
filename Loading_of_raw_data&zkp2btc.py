import bitcoinrpc
from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException
from py3.Chain import Chain
import sqlite3
import pandas as pd
import numpy as np
import datetime
import hashlib
from tqdm import tqdm

#Make a connection
rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:8332"%("username", "password"))
num_blocks = rpc_connection.getblockcount()
num_blocks

chunk_size = 10000
chunks = int(num_blocks / chunk_size)

# Function For Loading
def initial_load() :
    with sqlite3.connect('bitcoin_blockchain.db') as conn:
        for c in tqdm(range(0, chunks + 1)) :
            print('Loading chunk #{}'.format(c))
            block_stats = [rpc_connection.getblockstats(i) for i in range(c*chunk_size + 1, (c + 1)*chunk_size)]
            df = pd.DataFrame(block_stats)
            df['feerate_percentiles'] = df['feerate_percentiles'].astype(str)
            df.to_sql('blockchain', conn, if_exists = 'append') 
        print(f'finished {(c+1)*chunk_size} record')

# Function For Future Updates
def update_chain(start_block) :
    num_blocks = rpc_connection.getblockcount()
    block_stats = [rpc_connection.getblockstats(i) for i in range(start_block, num_blocks + 1)]
    df = pd.DataFrame(block_stats)
    df['feerate_percentiles'] = df['feerate_percentiles'].astype(str)
    with sqlite3.connect('bitcoin_blockchain.db') as conn :
        df.to_sql('blockchain', conn, if_exists = 'append') 
##update_chain(700000)

# Load 
initial_load()

# Launch to uploaded data 
cursor = sqlite3.connect('bitcoin_blockchain.db').cursor()

#View data
cursor.execute('SELECT * FROM blockchain LIMIT 1')
ts = cursor.fetchall()
# Show results 
for t in ts :
  print(t)

#View data
cursor.execute('SELECT COUNT(*) FROM blockchain')
ts = cursor.fetchall()
# Show results 
for t in ts :
  print(t)


# Save changes and close connection
sqlite3.connect('bitcoin_blockchain.db').commit()
sqlite3.connect('bitcoin_blockchain.db').close()


#####################################################
##### EXAMPLE OF IMPLEMENTATION ZK-SNARK TO BTC #####
#####################################################

import bitcoin
from bitcoin import *
from py_ecc.optimized_bn128 import G1, add, multiply, neg, curve_order
import hashlib

# Генерация секретного ключа и публичного адреса
secret_key = random_key()
public_key = privtopub(secret_key)
address = pubtoaddr(public_key)

print("Secret Key:", secret_key)
print("Public Key:", public_key)
print("Address:", address)

# Прост (Prover) хочет доказать, что он знает секретный ключ, не раскрывая его.
# Он выбирает случайное число r и вычисляет R = r * G
r = random_key()
R = multiply(G1, int(r, 16))

# Проверяющий (Verifier) генерирует случайное значение challenge
challenge = random_key()

# Прост вычисляет ответ s = r + challenge * secret_key (mod curve_order)
s = (int(r, 16) + int(challenge, 16) * int(secret_key, 16)) % curve_order

# Проверяющий проверяет, что s * G = R + challenge * Public Key
R_check = add(multiply(G1, s), neg(multiply(G1, int(challenge, 16) * int(secret_key, 16))))

print("R:", R)
print("R_check:", R_check)

if R == R_check:
    print("Zero-Knowledge Proof успешно проверено!")
else:
    print("Zero-Knowledge Proof не удалось проверить.")





