macro_rules! impl_for_enum {
    (
        enum $enum_name:ident {
            $(
                $variant_name:ident($variant_ty:ty),
            )*
        }
    ) => {
        impl GenerateHFMap for $enum_name {
            fn generate_hf_map(prefix: &str) -> HeaderFieldMap {
                let mut hf_map = HeaderFieldMap::new()
                    .add(prefix, "", stringify!{$enum_name}, FieldKind::Branch);
                $(
                    hf_map.extend(<$variant_ty>::generate_hf_map(&format!("{prefix}.{}", stringify!{$variant_name}.to_case(Case::Snake))));
                )*
                hf_map
            }
        }

        impl AddToTree for $enum_name {
            fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()> {
                match self {
                    $(
                        Self::$variant_name(body) => {
                            body.add_to_tree(
                                &format!("{prefix}.{}", stringify!{$variant_name}.to_case(Case::Snake)),
                                &args.make_subtree(prefix, &format!("{} ({})", stringify!{$enum_name}, stringify!{$variant_name}))?
                            )?;
                        }
                    )*
                    // _ => {
                    //     let raw_txt = format!("{:?}", &self);
                    //     let msg = raw_txt.split('(').next().unwrap().split('{').next().unwrap();
                    //     bail!("Not yet implemented for {}", msg)
                    // }
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
                #[dissect(expand)]
                $expand_name:ident: $expand_ty:ty,
            )*

            $(
                #[dissect(vec)]
                $vec_name:ident: Vec<$vec_ty:ty>,
            )*

            $(
                #[dissect(option)]
                $skip_name:ident: Option<$option_ty:ty>,
            )*

            $(
                #[dissect(enum)]
                $enum_name:ident: $enum_ty:ty,
            )*
        }
    ) => {
        impl GenerateHFMap for $struct_name {
            #![allow(unused)]
            fn generate_hf_map(prefix: &str) -> HeaderFieldMap {
                let mut hf_map = HeaderFieldMap::new()
                $(
                    .add(prefix, stringify!{$field_name}, &stringify!{$field_name}.to_case(Case::Title), FieldKind::Text)
                )*
                $(
                    .add(prefix, stringify!{$vec_name}, stringify!{$vec_ty}, FieldKind::Branch)
                )*
                $(
                    .add(prefix, stringify!{$enum_name}, stringify!{$enum_ty}, FieldKind::Text)
                )*
                ;

                $(
                    hf_map.extend(<$vec_ty>::generate_hf_map(&format!("{prefix}.{}", stringify!{$vec_name})));
                )*

                $(
                    hf_map.extend(<$expand_ty>::generate_hf_map(&format!("{prefix}.{}", stringify!{$expand_name})));
                )*

                hf_map
            }
        }

        impl AddToTree for $struct_name {
            #![allow(unused)]
            fn add_to_tree(&self, prefix: &str, args: &TreeArgs) -> Result<()> {
                $(
                    let hf_index = args.get_hf(&format!("{prefix}.{}", stringify!{$field_name}))?;
                    unsafe {
                        epan_sys::proto_tree_add_string(
                            args.tree,
                            hf_index,
                            args.tvb,
                            args.start as _,
                            args.length as _,
                            nul_terminated_str(&format!("{:?}", self.$field_name))?,
                        );
                    }
                )*

                $(
                    for item in &self.$vec_name {
                        item.add_to_tree(
                            &format!("{prefix}.{}", stringify!{$vec_name}),
                            args,
                        )?;
                    }
                )*

                $(
                    self.
                        $expand_name
                        .add_to_tree(
                            &format!("{prefix}.{}", stringify!{$expand_name}),
                            args,
                        )?;
                )*

                Ok(())
            }
        }
    };
}

pub(crate) use impl_for_enum;
pub(crate) use impl_for_struct;
