//
// Copyright (c) 2026 ZettaScale Technology
//
// This program and the accompanying materials are made available under the
// terms of the Eclipse Public License 2.0 which is available at
// http://www.eclipse.org/legal/epl-2.0, or the Apache License, Version 2.0
// which is available at https://www.apache.org/licenses/LICENSE-2.0.
//
// SPDX-License-Identifier: EPL-2.0 OR Apache-2.0
//
// Contributors:
//   ZettaScale Zenoh Team, <zenoh@zettascale.tech>
//

macro_rules! impl_for_enum {
    (
        enum $enum_name:ident {
            $(
                $variant_name:ident($variant_ty:ty),
            )*
        }
    ) => {
        impl Registration for $enum_name {
            fn generate_hf_map(prefix: &str) -> HeaderFieldMap {
                let mut hf_map = HeaderFieldMap::new();
                $(
                    {
                        let variant_prefix = format!("{prefix}.{}", stringify!{$variant_name}.to_case(Case::Snake));
                        hf_map = hf_map.add(variant_prefix.clone(), stringify!{$variant_name}, FieldKind::Branch);
                        hf_map.extend(<$variant_ty>::generate_hf_map(&variant_prefix));
                    }
                )*
                hf_map
            }

            fn generate_subtree_names(prefix: &str) -> Vec<String> {
                let mut names = vec![];
                $(
                    {
                        let variant_prefix = format!("{prefix}.{}", stringify!{$variant_name}.to_case(Case::Snake));
                        names.push(variant_prefix.clone());
                        names.extend(<$variant_ty>::generate_subtree_names(&variant_prefix));
                    }
                )*
                names
            }
        }

        impl AddToTree for $enum_name {
            fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()> {
                match self {
                    $(
                        Self::$variant_name(body) => {
                            let variant_prefix = format!("{prefix}.{}", stringify!{$variant_name}.to_case(Case::Snake));
                            body.add_to_tree(
                                &variant_prefix,
                                &args.make_subtree(
                                    &variant_prefix,
                                    &format!("{} ({})",
                                    // Map "TransportBody" to "Transport", etc.
                                    stringify!{$enum_name}.trim_end_matches("Body"),
                                    stringify!{$variant_name})
                                )?
                            )?;
                        }
                    )*
                }
                Ok(())
            }
        }
    };
}

macro_rules! impl_for_struct {
    (
        struct $struct_name:ident {
            $(
                $field_name:ident: $field_ty:ty,
            )*

            $(
                #[dissect(expand_as = $expand_as:literal)]
                $expand_as_field:ident: $expand_as_ty:ty,
            )*

            $(
                #[dissect(expand)]
                $expand_field:ident: $expand_ty:ty,
            )*

            $(
                #[dissect(expand_vec_as = $expand_vec_as:literal)]
                $expand_vec_as_field:ident: Vec<$expand_vec_as_ty:ty>,
            )*
        }
    ) => {
        const _: () = {
            $(
                assert!(!$expand_as.is_empty(), "expand_as argument should be non-empty");
            )*

            $(
                assert!(!$expand_vec_as.is_empty(), "expand_vec_as argument should be non-empty");
            )*
        };

        impl Registration for $struct_name {
            #![allow(unused)]
            fn generate_hf_map(prefix: &str) -> HeaderFieldMap {
                let mut hf_map = HeaderFieldMap::new()
                $(
                    .add(
                        format!("{}.{}", prefix, stringify!{$field_name}),
                        &stringify!{$field_name}.to_case(Case::Title),
                        FieldKind::Text
                    )
                )*
                ;

                $(
                    {
                        let vec_prefix = format!("{prefix}.{}", $expand_vec_as);
                        hf_map = hf_map.add(
                            vec_prefix.clone(),
                            stringify!{$expand_vec_as_ty},
                            FieldKind::Branch,
                        );
                        hf_map.extend(<$expand_vec_as_ty>::generate_hf_map(&vec_prefix));
                    }
                )*

                $(
                    hf_map.extend(<$expand_as_ty>::generate_hf_map(&format!("{prefix}.{}", $expand_as)));
                )*

                $(
                    hf_map.extend(<$expand_ty>::generate_hf_map(prefix));
                )*

                hf_map
            }

            fn generate_subtree_names(prefix: &str) -> Vec<String> {
                let mut names = vec![];

                $(
                    {
                        let vec_prefix = format!("{prefix}.{}", $expand_vec_as);
                        names.push(vec_prefix.clone());
                        names.extend(<$expand_vec_as_ty>::generate_subtree_names(&vec_prefix));
                    }
                )*

                $(
                    {
                        let exp_prefix = format!("{prefix}.{}", $expand_as);
                        names.push(exp_prefix.clone());
                        names.extend(<$expand_as_ty>::generate_subtree_names(&exp_prefix));
                    }
                )*

                $(
                    names.extend(<$expand_ty>::generate_subtree_names(prefix));
                )*

                names
            }
        }

        impl AddToTree for $struct_name {
            #![allow(unused)]
            fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()> {
                $(
                    let hf_index = args.get_hf(&format!("{prefix}.{}", stringify!{$field_name}))?;
                    let field_key = format!("{prefix}.{}", stringify!{$field_name});
                    let (field_start, field_len) = args.field_span(&field_key);
                    unsafe {
                        let field_name_c_str = std::ffi::CString::new(format!("{:?}", self.$field_name)).unwrap();
                        // The codec doesn't expose per-field byte offsets, so we prevent wireshark
                        // from displaying it by setting length to 0.
                        epan_sys::proto_tree_add_string(
                            args.tree,
                            hf_index,
                            args.tvb,
                            field_start as _,
                            field_len as _,
                            field_name_c_str.as_ptr(),
                        );
                    }
                )*

                // HACK(fuzzypixelz): recursively created trees will have an incorrect length. Only
                // the Transport layer has an accurate length.
                let args = $crate::tree::TreeArgs { length: 0, local_spans: None, ..*args };

                $(
                    for item in &self.$expand_vec_as_field {
                        item.add_to_tree(
                            &format!("{prefix}.{}", $expand_vec_as),
                            &args,
                        )?;
                    }
                )*

                $(
                    self.$expand_as_field.add_to_tree(
                        &format!("{prefix}.{}", $expand_as),
                        &args,
                    )?;
                )*

                $(
                    self.$expand_field.add_to_tree(prefix, &args)?;
                )*

                Ok(())
            }
        }
    };
}

pub(crate) use impl_for_enum;
pub(crate) use impl_for_struct;
