extern crate proc_macro;
extern crate syn;
#[macro_use]
extern crate quote;

use proc_macro::TokenStream;

#[proc_macro_derive(Syscall)]
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
        let ident = var.ident;
        let fields = match var.data {
            syn::VariantData::Struct(v) => v,
            _ => panic!("Syscall should use only struct variants"),
        };
        let fieldnames: Vec<_> = fields.iter().map(|f| &f.ident).collect();
        let fieldnames2 = fieldnames.clone();
        let mut writefmt = format!("{}(", ident).to_lowercase();
        writefmt.push_str(&vec!["{}"; fields.len()].join(", "));
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
