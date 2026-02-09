
use proc_macro::TokenStream;
use quote::quote;

fn build_hex_trait_impls(item: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let ident = &input.ident;

    (quote! {
        impl core::fmt::LowerHex for #ident {
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
#[proc_macro_derive(Hex)]
pub fn derive_hex(item: TokenStream) -> TokenStream {
    build_hex_trait_impls(item)
}

/// 在 `Hex` 基础上派生 `Debug`，并复用十六进制输出格式。
#[proc_macro_derive(HexDebug)]
pub fn derive_hex_debug(item: TokenStream) -> TokenStream {
    let mut hex_trait_tokens: TokenStream = build_hex_trait_impls(item.clone());
    let input = syn::parse_macro_input!(item as syn::DeriveInput);
    let ident = &input.ident;

    let dbg: TokenStream = (quote! {
    impl core::fmt::Debug for #ident {
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
