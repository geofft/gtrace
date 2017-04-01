extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;

#[proc_macro_derive(Syscall, attributes(syscall))]
pub fn derive_syscall(input: TokenStream) -> TokenStream {
    let ast = syn::parse_derive_input(&input.to_string()).unwrap();
    let gen = match ast.body {
        syn::Body::Struct(_) => panic!("Syscall should be an enum"),
        syn::Body::Enum(variants) => handle(&ast.ident, variants)
    };
    gen.parse().unwrap()
}

fn handle(name: &syn::Ident, variants: Vec<syn::Variant>) -> quote::Tokens {
    let mut arms = vec![];
    for var in variants {
        let ident = &var.ident;
        let fields = match var.data {
            syn::VariantData::Struct(ref v) => v,
            _ => panic!("Syscall should use only struct variants"),
        };
        let fieldnames: Vec<_> = fields.iter().map(|f| &f.ident).collect();
        let fieldnames2 = fieldnames.clone();
        let mut writefmt = format!("{}(", ident).to_lowercase();
        let mut len = fields.len();
        if is_unknown(&var) {
            writefmt = "syscall_{}(".to_owned();
            len -= 1;
        }
        writefmt.push_str(&vec!["{}"; len].join(", "));
        writefmt.push_str(")");
        let writefmtlit = syn::Lit::Str(writefmt, syn::StrStyle::Cooked);
        arms.push(quote! {
            &#name::#ident {#(ref #fieldnames),*} => write!(formatter, #writefmtlit, #(#fieldnames2),*)
        });
    }
    quote! {
        impl ::std::fmt::Display for #name {
            fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                match self {
                    #(#arms,)*
                }
            }
        }
    }
}

fn is_unknown(var: &syn::Variant) -> bool {
    for attr in &var.attrs {
        if let syn::MetaItem::List(ref name, ref items) = attr.value {
            if name == "syscall" {
                for subattr in items {
                    if let &syn::NestedMetaItem::MetaItem(syn::MetaItem::Word(ref ident)) = subattr {
                        if ident == "unknown" {
                            return true;
                        }
                    }
                }
            }
        }
    }
    return false;
}
