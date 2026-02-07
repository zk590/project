// 公共常量定义文件

// 定义树的高度
pub const TREE_HEIGHT: usize = 22;

// 定义电路容量
pub const CAPACITY: usize = 16;

// 定义密钥路径
pub const PUB_KEY_PATH: &str = "/opt/project/1-Sender/ecies/ecies-pub.der";
pub const PRIV_KEY_PATH: &str = "/opt/project/1-Sender/ecies/ecies-priv.der";

// 文件路径常量
// pub const MERKLE_FILE: &str = "/opt/project/1-Sender/merkle/merkle_data.bin"; //跟随叶子节点变化

pub const MERKLE_FILE: &str = "/opt/project/1-Sender/merkle/merkle_data.bin"; //跟随叶子节点变化
pub const MERKLE_SOME_FILE: &str = "/opt/project/1-Sender/merkle/merkle_some_data.bin"; //跟随叶子节点变化
pub const MERKLE_TREE_STATE_FILE: &str = "/opt/project/1-Sender/merkle/merkle_tree_state.bin"; //存储Merkle树状态，用于持久化

pub const PLONK_PROOF_FILE: &str = "/opt/project/3-Plonk/merkle-plonk/plonk_proof_1.bin"; //plonk 证明,跟随叶子节点变化
pub const PLONK_PUBLICINPUTS_FILE: &str = "/opt/project/3-Plonk/merkle-plonk/plonk_publicinputs_1.bin"; //plonk 公共输入，跟随叶子节点变化

// 定义电路证明文件路径
pub const CIRCUIT_PROVE_FILE: &str = "/opt/project/3-Plonk/merkle-plonk/circuit_prove.bin"; //跟随容量值变化
pub const VERIFIER_FILE: &str = "/opt/project/3-Plonk/merkle-plonk/verifier.bin"; //跟随容量值变化



// sha2哈希路径
pub const SHA2_HASH_FILE: &str = "/opt/project/1-Sender/sha2/sha2_hash.bin";
pub const SHA2_HASH_BATCH_FILE: &str = "/opt/project/1-Sender/sha2/sha2_batch_hash.bin";
pub const SHA2_MESSAGE_FILE: &str = "/opt/project/1-Sender/sha2/messages.txt";

pub const KECCAK_HASH_FILE: &str = "/opt/project/1-Sender/keccak/keccak_hash.bin";
pub const KECCAK_HASH_BATCH_FILE: &str = "/opt/project/1-Sender/keccak/keccak_batch_hash.bin";
pub const KECCAK_MESSAGE_FILE: &str = "/opt/project/1-Sender/keccak/messages.txt";

pub const RSA_HASH_FILE: &str = "/opt/project/1-Sender/rsa/rsa_hash.bin";
pub const RSA_HASH_BATCH_FILE: &str = "/opt/project/1-Sender/rsa/rsa_batch_hash.bin";

// sha3哈希路径
pub const SHA3_HASH_FILE: &str = "/opt/project/1-Sender/sha3/sha3_hash.bin";
pub const SHA3_HASH_BATCH_FILE: &str = "/opt/project/1-Sender/sha3/sha3_batch_hash.bin";
pub const SHA3_MESSAGE_FILE: &str = "/opt/project/1-Sender/sha3/messages.txt";


// ecdsa路径
pub const ECDSA_DATA_FILE: &str = "/opt/project/1-Sender/ecdsa/ecdsa_data.bin";
pub const ECDSA_BATCH_DATA_FILE: &str = "/opt/project/1-Sender/ecdsa/ecdsa_batch_data.bin";

// schnorr路径
pub const SCHNORR_DATA_FILE: &str = "/opt/project/1-Sender/schnorr/schnorr_data.bin";
pub const SCHNORR_BATCH_DATA_FILE: &str = "/opt/project/1-Sender/schnorr/schnorr_batch_data.bin";

pub const FIBONACCI_DATA_FILE: &str = "/opt/project/1-Sender/fibonacci_add/fibonacci_data.bin";

pub const FIBONACCI_MUL_DATA_FILE: &str = "/opt/project/1-Sender/fibonacci_mul/fibonacci_mul_data.bin";


// 定义Merkle树证明文件路径前缀
pub const MERKLE_PROOF_FILE_PREFIX: &str = "/opt/project/3-Plonk/merkle-plonk/"; //跟随叶子节点变化