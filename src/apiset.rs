use std::collections::HashMap;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct APISetNamespace {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    entry_offset: u32,
    hash_offset: u32,
    hash_multi
}

#[derive(Default, Clone, Debug)]
pub struct APISet {
    mapping: HashMap<String, String>,
}

impl APISet {
    pub fn new() -> APISet {
        return APISet::default();
    }
}

pub fn parse_apiset(apiset_dll: super::pe::PE) -> Result<APISet, Box<dyn std::error::Error>> {
    let mut apiset: APISet = APISet::new();

    let apiset_section = apiset_dll
        .sections
        .get(".apiset")
        .expect("Cannot find .apiset section in apiset dll");

    let mut cursor = std::io::Cursor::new(&apiset_dll.data);

    let section_start = apiset_section.header.ptr_to_raw_data;
    let section_va = apiset_section.header.virtual_address;

    return Ok(apiset);
}
