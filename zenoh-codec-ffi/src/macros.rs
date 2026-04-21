/// Generate `Registration` impl for an enum type.
/// Each variant becomes a Branch node in the field map.
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
    };
}

/// Generate `Registration` impl for a struct type.
/// Plain fields become Text nodes; expand_as/expand/expand_vec_as produce subtrees.
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
    };
}

pub(crate) use impl_for_enum;
pub(crate) use impl_for_struct;
