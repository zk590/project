#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::prelude::{Composer, Error};

use super::compress::CompressedCircuit;

pub trait Circuit: Default {
    /// 在给定 `Composer` 上定义电路约束。
    /// 实现者需要把业务逻辑转换为门约束并写入 composer。
    /// 返回错误表示电路构建阶段失败，编译/证明流程应立即中止。
    fn circuit(&self, composer: &mut Composer) -> Result<(), Error>;

    /// 估算当前电路的约束数量。
    /// 该实现会实例化一个临时 composer 并执行一次电路构建。
    /// 若构建失败则返回 0，调用方可据此决定是否继续流程。
    fn size(&self) -> usize {
        let mut size_estimation_composer = Composer::initialized();
        match self.circuit(&mut size_estimation_composer) {
            Ok(_) => size_estimation_composer.constraints(),
            Err(_) => 0,
        }
    }

    #[cfg(feature = "alloc")]
    /// 生成当前电路的压缩描述字节。
    /// 该流程会用默认实例构建电路，并通过 `CompressedCircuit` 做结构压缩。
    /// 输出可用于跨进程传输或缓存，后续可反序列化回 `Composer`。
    fn compress() -> Result<Vec<u8>, Error> {
        let mut compression_composer = Composer::initialized();
        Self::default().circuit(&mut compression_composer)?;

        let enable_hades_optimization = true;
        Ok(CompressedCircuit::from_composer(
            enable_hades_optimization,
            compression_composer,
        ))
    }
}
