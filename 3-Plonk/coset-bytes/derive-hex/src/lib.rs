
use proc_macro::TokenStream;
use quote::quote;

#[proc_macro_derive(Hex)]
pub fn derive_hex(item: TokenStream) -> TokenStream {
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

#[proc_macro_derive(HexDebug)]
pub fn derive_hex_debug(item: TokenStream) -> TokenStream {
    let mut hex: TokenStream = derive_hex(item.clone());
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

    hex.extend(dbg);
    hex
}
