use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HeaderField {
    pub name: String,
    pub kind: FieldKind,
}

type Hfm = HashMap<String, HeaderField>;
pub struct HeaderFieldMap(Hfm);

impl std::ops::Deref for HeaderFieldMap {
    type Target = Hfm;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for HeaderFieldMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl IntoIterator for HeaderFieldMap {
    type Item = <Hfm as IntoIterator>::Item;
    type IntoIter = <Hfm as IntoIterator>::IntoIter;
    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl HeaderFieldMap {
    pub fn new() -> Self {
        HeaderFieldMap(Hfm::new())
    }

    pub fn add(mut self, key: String, display_name: &str, kind: FieldKind) -> Self {
        self.0.insert(
            key,
            HeaderField {
                name: display_name.into(),
                kind,
            },
        );
        self
    }
}

#[derive(Debug, Copy, Clone)]
pub enum FieldKind {
    Text,
    Branch,
    // Number,
    // Bytes,
}

pub trait Registration {
    fn generate_hf_map(prefix: &str) -> HeaderFieldMap;
    fn generate_subtree_names(prefix: &str) -> Vec<String>;
}
