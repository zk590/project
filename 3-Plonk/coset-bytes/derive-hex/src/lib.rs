use proc_macro::TokenStream;
use quote::quote;

/// 生成 `LowerHex` 与 `UpperHex` 两个格式化 trait 的实现代码。
/// 该函数属于过程宏内部代码生成入口：先解析派生目标类型，再拼装 token。
/// 生成后的实现统一依赖 `to_bytes()`
/// 输出，确保十六进制展示与底层序列化保持一致。
fn build_hex_trait_impls(item: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let ident = &input.ident;

    (quote! {
        impl core::fmt::LowerHex for #ident {
            /// 以小写十六进制输出类型的字节表示。
            /// 若格式化参数带 `#`，会额外输出 `0x` 前缀。
            /// 该实现逐字节编码，保证输出长度与底层字节长度严格对应。
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let bytes = self.to_bytes();

                if f.alternate() {
                    write!(f, "0x")?
                }

                for byte in &bytes[..] {
                    write!(f, "{:02x}", &byte)?
                }

                Ok(())
            }
        }

        impl core::fmt::UpperHex for #ident {
            /// 以大写十六进制输出类型的字节表示。
            /// 若格式化参数带 `#`，会额外输出 `0x` 前缀。
            /// 大小写仅影响字符展示，不改变字节语义与顺序。
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                let bytes = self.to_bytes();

                if f.alternate() {
                    write!(f, "0x")?
                }

                for byte in &bytes[..] {
                    write!(f, "{:02X}", &byte)?
                }

                Ok(())
            }
        }
    })
    .into()
}

/// 为类型自动派生 `LowerHex` / `UpperHex` 格式化实现。
/// 该宏用于“只需要十六进制显示能力”的场景，不额外改变 `Debug` 语义。
/// 派生后可直接使用 `{:x}`、`{:X}` 和 `#` 前缀格式，输出稳定的字节十六进制串。
/// 宏本身不感知业务字段结构，仅要求目标类型提供 `to_bytes` 能力。
#[proc_macro_derive(Hex)]
pub fn derive_hex(item: TokenStream) -> TokenStream {
    build_hex_trait_impls(item)
}

/// 在 `Hex` 基础上派生 `Debug`，并复用十六进制输出格式。
/// 该宏先复用 `Hex` 的代码生成，再补充 `Debug` 的自定义格式实现。
/// 默认 `Debug` 输出小写十六进制；当检测到内部大写标志时切换为大写输出。
/// 这种设计让调试日志与十六进制展示规则保持一致，
/// 减少多套显示逻辑带来的维护成本。
#[proc_macro_derive(HexDebug)]
pub fn derive_hex_debug(item: TokenStream) -> TokenStream {
    let mut hex_trait_tokens: TokenStream = build_hex_trait_impls(item.clone());
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let ident = &input.ident;

    let dbg: TokenStream = (quote! {
    impl core::fmt::Debug for #ident {
        /// 统一 `Debug` 输出到十六进制路径，便于二进制类型调试。
        /// 默认使用小写格式；检测到内部标志时切换到大写。
        /// 该实现避免了与 `Hex` 输出语义分叉，便于日志比对与排障。
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {

            let debug_upper_hex_flag_index = 5_u32;

            #[allow(deprecated)]
            if f.flags() & (1 << debug_upper_hex_flag_index) !=0 {
                core::fmt::UpperHex::fmt(self, f)
            } else {
                core::fmt::LowerHex::fmt(self, f)
            }
        }
    }})
    .into();

    hex_trait_tokens.extend(dbg);
    hex_trait_tokens
}
