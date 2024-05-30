extern crate core;

use proc_macro::{Span, TokenStream};

use quote::{quote, ToTokens};
use regex::Regex;
use syn::{DeriveInput, Field, LitStr, parse_macro_input};
use syn::Data::Struct;
use syn::DataStruct;
use syn::Fields::Named;
use syn::FieldsNamed;

fn parse_serde_rename_attr(field: &&Field) -> Option<String> {
    let mut out: LitStr = LitStr::new("", Span::call_site().into());
    let attr = field.attrs.iter().find(|attr| {
        if attr.path().is_ident("serde") {
            return match attr.parse_nested_meta(|meta| {
                match meta.path.is_ident("rename") {
                    true => {
                        let value = meta.value()?;
                        let s: LitStr = value.parse()?;
                        out = s;
                        Ok(())
                    }
                    false => Err(meta.error("not rename")),
                }
            }) {
                Err(_) => false,
                Ok(_) => true
            };
        }
        return false;
    });
    match attr {
        Some(_) => Some(out.value().to_string()),
        None => None,
    }
}

#[proc_macro_derive(Checksum)]
pub fn checksumable(item: TokenStream) -> TokenStream {
    let re = Regex::new(r"str|Str|u\d|bool|i\d").unwrap();
    let ast = parse_macro_input!(item as DeriveInput);
    let name = ast.ident.clone();
    let fields = match ast.data {
        Struct(DataStruct { fields: Named(FieldsNamed { ref named, .. }), .. }) => named,
        _ => unimplemented!("Only works for structs"),
    };

    let mut builder_fields: Vec<&Field> = fields.iter().collect();
    let format_string = "{}".to_string().repeat(builder_fields.len() + 1);
    builder_fields.sort_by(|f, fb| {
        let rename_a = parse_serde_rename_attr(f);
        let rename_b = parse_serde_rename_attr(fb);

        match rename_a {
            Some(r) => {
                match rename_b {
                    Some(rb) => r.cmp(&rb),
                    None => r.cmp(&fb.ident.clone().unwrap().to_string())
                }
            }
            None => {
                match rename_b {
                    Some(rb) => f.ident.clone().unwrap().to_string().cmp(&rb),
                    None => f.ident.clone().unwrap().to_string().cmp(&fb.ident.clone().unwrap().to_string())
                }
            }
        }
    });
    let fucked = builder_fields.iter().map(|f| {
        let field_name = &f.ident;
        let field_type = &f.ty;
        match re.find(&field_type.to_token_stream().to_string()) {
            Some(m) => {
                if m.start() != 0 {
                    quote! { String::new() }
                } else {
                    match field_type.to_token_stream().to_string().to_ascii_lowercase().contains("option") {
                        true => quote! { &self.#field_name.clone().unwrap_or_default() },
                        false => quote! { &self.#field_name },
                    }
                }
            }
            None => quote! { String::new() },
        }
    });

    let signature_impl = quote! {
        impl Checksum for #name {
            fn hashable_string(&self, salt: &str) -> String {
                format!(#format_string, #(#fucked,)* salt)
            }

            fn get_sig(&self, salt: &str) -> String {
                let to_hash = self.hashable_string(salt);
                let mut hasher = Sha256::new();
                hasher.update(to_hash);
                format!("{:x}", hasher.finalize())
            }
        }
    };

    signature_impl.into()
}

