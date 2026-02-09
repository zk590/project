1-Sender:

##Sha3程序
cd /opt/project/1-Sender/sha3
cargo run --bin sha3_batch -- --input-file messages.txt

##Sha2程序
cd /opt/project/1-Sender/sha2
cargo run --bin sha2_batch -- --input-file messages.txt

##fibonacci_add
cd /opt/project/1-Sender/fibonacci_add
cargo run -- --n 12

##fibonacci_mul
cd /opt/project/1-Sender/fibonacci_mul
cargo run -- --n 12

##merkle
cd /opt/project/1-Sender/merkle
cargo run --bin some_merkle  -- --Some 3 3


#ecdsa 
cargo run --bin ecdsa_batch -- --input-file messages.txt


##3-Plonk
cd /opt/project/3-Plonk/merkle-plonk
cargo run --bin batch_merkle_proof



## 2-Receiver/plonk
cd /opt/project/2-Receiver/Plonk
cargo run

## 2-Receiver/zkMIPS
cd /opt/project/2-Receiver/zkMIPS/Plonk/host
cargo run --release -- --algorithm fibonacci-add

cargo run --release -- --algorithm sha2




## 4-zkMIPS

##fibonacci_add
cd /opt/project/4-zkMIPS/fibonacci_add/host

cargo run -- --execute

cargo run --release -- --core

cargo run --release -- --system plonk

## fibonacci_mul
cd /opt/project/4-zkMIPS/fibonacci_mul/host

cargo run -- --execute

cargo run --release -- --core

##sha2
cd /opt/project/4-zkMIPS/sha2/host

## merkle
cd /opt/project/4-zkMIPS/merkle/host

cargo run -- --execute

cargo run --release -- --core

cargo run --release -- --system plonk

##aggregation
cd /opt/project/4-zkMIPS/aggregation/host && source /etc/profile && cargo run --release -- fibonacci_add sha2




























#keccak
cd /opt/project/1-Sender/keccak
cargo run --bin keccak_batch -- --input-file messages.txt





cargo run --bin ecdsa -- --message "Hello, world!"

cargo run --bin ecdsa_batch -- --input-file messages.txt
## 运行ECIES加密程序
cargo run --bin ecies -- --input-file messages.txt

cargo run --bin ecies -- --input-file /opt/sp10924/1-Sender/common/test_1m_text.txt

# 运行Keccak哈希程序
cargo run --bin keccak_batch -- --input-file messages.txt
cargo run --bin keccak_batch -- --input-file /opt/sp10924/1-Sender/common/test_1m_text.txt

# 运行RSA哈希程序
cargo run --bin rsa_batch -- --input-file messages.txt
cargo run --bin rsa_batch -- --input-file /opt/sp10924/1-Sender/common/test_1m_text.txt

# 运行Schnorr哈希程序
cargo run --bin schnorr_batch -- --input-file messages.txt
cargo run --bin schnorr_batch -- --input-file /opt/sp10924/1-Sender/common/test_1m_text.txt

# 运行SHA2哈希程序
cargo run --bin sha2_batch -- --input-file messages.txt
cargo run --bin sha2_batch -- --input-file /opt/sp10924/1-Sender/common/test_1m_text.txt

cargo run --bin sha3_batch -- --input-file messages.txt
cargo run --bin sha3_batch -- --input-file /opt/sp10924/1-Sender/common/test_1m_text.txt

# 运行Merkle树程序
cargo run --bin some_merkle -- --Some 10 5

# 运行Merkle证明程序
cd /opt/project/3-Plonk/merkle-plonk
cargo run --bin batch_merkle_proof

# 运行Merkle验证程序
cd /opt/project/2-Receiver/Plonk
cargo run -- 5

cargo test test_invalid_proof_file_path -- --nocapture


cargo test test_modify_proof_file -- --nocapture
cargo test test_corrupted_proof_file -- --nocapture



zkVM 程序：

cd /opt/project/4-zkVM/keccak/script
cargo run --release --bin keccak-script



85fdfae4d2c97592f4eecf10af9ee00648bbdb4d7bda3d33bf968fd271139e3156c5f2c53ddb2dd321448fb70002d569b832a5f8c389fdd6b3c52097ac72fb069b70a16248876bf1594be748def846a658bc8908ab317c540a005f69350d6f8e89d1780e563f5657601465aa93b3581756c9380f9fc14fc2fb79b0f155be585e85ecf5531c99a8b6266fdb4fd122a886b48cc24b5c1df47d67a612a6bc9e5fea1e64d65f559592dd6b74d6e6a3806db54b978b17f4790fe2e25201b88ae4fa7f804af3687acec4934af9b06da4f81641f659e4ed25a3623c0fcabb995f28a2f6ad989ce926b65c63f057b74d1ffd97ec90a3571c7c686e526efbfb7eb6a58a93e075b261c72be37e424dc8342a4e1ba7e3c3fbb3976e3baffb25f1f502aa52a2a19aebcdc440379c2d9f31def9c36ba8a4b18cd573ff8c5bc0f0d34225a656c604dd60d9a465d8ab488eee959a7d6553a5317a2f91d45845cff3a84d59fe6ec782a79cd5eeb2ae6544a6c9bca7ee563569fa1d5fcd43398161bedc12556cfc5d8f76d253f673571660ad1dabb8e33856623161896e3c9510dc58d73309046111f269fc8525130c8e3a97c63819bf177daa327d42432123a37dbd5ef9c1afcabaf382f72e6cd23e3cd4f69c0696363da5b5407bf5630887e2513d0b1e25d4b63eb9aeab5285926c15f415c119504b564124645034e3bb70f6ff37ed34cd406f09481f1d0f2c12a303463aa6f8a2b2d9ba293a02aa604794b7fe838923f863eb7130d92055914d766ffbb323e3378f4e504e8d2aaef390d5682e562013ef3d075c084a52947ce0cad546ac98afa4c1de53cb74165ea6c78ee4e5598e0750de836e9ff3f0eb8ebf11aef8990117126ba73510e6a434f5250ac114f2bd7dd89a3053ef2e7b6c32f19b1de1823d246e57986d25a03c9e1da9171a6d137891979ec6852542b0e8e4dff69b6b4fe2f25e4bc1659e2fbfbf14edcc82c06f4f0d12409553c3d932829db236a8464bbef6c8a9971bd50c762df9d46450138ca796393d479bc68be9b6b44bb2634577a8d6ada293512c0d6482381c9cf9caebeb06d659eab5e90e0730212288d401aaba1d4f853a4c7b773adb355aaa8acdc78fbf1cb40b9a257a627d2c0e95c9c1846eefefe10e419ddb38e4aa584d8c84258faa05b9d76d0f33da26c6448d3c2e0113d7d68d983b62f2a6b4e1563e4b00d7232059fdaa5f8c504dcc565f5f3672e934627bc9e8407e82d00955bb6067735a8df486c19e60337b836bd75884fc903c8e14016ffd27e86a3cca52b8d88c4679f18a9a242342647126691412a87daaa57b5f9dfcb13d8461b74ecd86f5dfb92dae1e18c66ba6c85d5f3ebf18bbbafd2b51dea2b34819c2836a192dc24da244661305a43a651ab29045498c3552b840cc8fa76f183254
85fdfae4d2c97592f4eecf10af9ee00648bbdb4d7bda3d33bf968fd271139e3156c5f2c53ddb2dd321448fb70002d569b832a5f8c389fdd6b3c52097ac72fb069b70a16248876bf1594be748def846a658bc8908ab317c540a005f69350d6f8e89d1780e563f5657601465aa93b3581756c9380f9fc14fc2fb79b0f155be585e85ecf5531c99a8b6266fdb4fd122a886b48cc24b5c1df47d67a612a6bc9e5fea1e64d65f559592dd6b74d6e6a3806db54b978b17f4790fe2e25201b88ae4fa7f804af3687acec4934af9b06da4f81641f659e4ed25a3623c0fcabb995f28a2f6ad989ce926b65c63f057b74d1ffd97ec90a3571c7c686e526efbfb7eb6a58a93e075b261c72be37e424dc8342a4e1ba7e3c3fbb3976e3baffb25f1f502aa52a2a19aebcdc440379c2d9f31def9c36ba8a4b18cd573ff8c5bc0f0d34225a656c604dd60d9a465d8ab488eee959a7d6553a5317a2f91d45845cff3a84d59fe6ec782a79cd5eeb2ae6544a6c9bca7ee563569fa1d5fcd43398161bedc12556cfc5d8f76d253f673571660ad1dabb8e33856623161896e3c9510dc58d73309046111f269fc8525130c8e3a97c63819bf177daa327d42432123a37dbd5ef9c1afcabaf382f72e6cd23e3cd4f69c0696363da5b5407bf5630887e2513d0b1e25d4b63eb9aeab5285926c15f415c119504b564124645034e3bb70f6ff37ed34cd406f09481f1d0f2c12a303463aa6f8a2b2d9ba293a02aa604794b7fe838923f863eb7130d92055914d766ffbb323e3378f4e504e8d2aaef390d5682e562013ef3d075c084a52947ce0cad546ac98afa4c1de53cb74165ea6c78ee4e5598e0750de836e9ff3f0eb8ebf11aef8990117126ba73510e6a434f5250ac114f2bd7dd89a3053ef2e7b6c32f19b1de1823d246e57986d25a03c9e1da9171a6d137891979ec6852542b0e8e4dff69b6b4fe2f25e4bc1659e2fbfbf14edcc82c06f4f0d12409553c3d932829db236a8464bbef6c8a9971bd50c762df9d46450138ca796393d479bc68be9b6b44bb2634577a8d6ada293512c0d6482381c9cf9caebeb06d659eab5e90e0730212288d401aaba1d4f853a4c7b773adb355aaa8acdc78fbf1cb40b9a257a627d2c0e95c9c1846eefefe10e419ddb38e4aa584d8c84258faa05b9d76d0f33da26c6448d3c2e0113d7d68d983b62f2a6b4e1563e4b00d7232059fdaa5f8c504dcc565f5f3672e934627bc9e8407e82d00955bb6067735a8df486c19e60337b836bd75884fc903c8e14016ffd27e86a3cca52b8d88c4679f18a9a242342647126691412a87daaa57b5f9dfcb13d8461b74ecd86f5dfb92dae1e18c66ba6c85d5f3ebf18bbbafd2b51dea2b34819c2836a192dc24da244661305a43a651ab29045498c3552b840cc8fa76f183254

cd /opt/project/5-zkMIPS/fibonacci_add/host && cargo run --release -- --system plonk


cd /opt/project/2-Receiver/zkMIPS/Plonk/host && cargo run -- --algorithm fibonacci-add
