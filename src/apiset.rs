use byteorder::LittleEndian;
use byteorder::ReadBytesExt;
use std::collections::HashMap;
use std::io::Read;
use std::io::Seek;

const APISetSchemaDLLPath: &str = "C:\\Windows\\System32\\apisetschema.dll";

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct APISetNamespace {
    version: u32,
    size: u32,
    flags: u32,
    count: u32,
    entry_offset: u32,
    hash_offset: u32,
    hash_multiplier: u32,
}

impl APISetNamespace {
    pub fn new() -> APISetNamespace {
        return APISetNamespace::default();
    }

    pub fn from_parser(
        cursor: &mut std::io::Cursor<&Vec<u8>>,
    ) -> Result<APISetNamespace, Box<dyn std::error::Error>> {
        let mut asn = APISetNamespace::new();

        asn.version = cursor.read_u32::<LittleEndian>()?;
        asn.size = cursor.read_u32::<LittleEndian>()?;
        asn.flags = cursor.read_u32::<LittleEndian>()?;
        asn.count = cursor.read_u32::<LittleEndian>()?;
        asn.entry_offset = cursor.read_u32::<LittleEndian>()?;
        asn.hash_offset = cursor.read_u32::<LittleEndian>()?;
        asn.hash_multiplier = cursor.read_u32::<LittleEndian>()?;

        return Ok(asn);
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct APISetNamespaceEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    hashed_length: u32,
    value_offset: u32,
    value_count: u32,
}

impl APISetNamespaceEntry {
    pub fn new() -> APISetNamespaceEntry {
        return APISetNamespaceEntry::default();
    }

    pub fn from_parser(
        cursor: &mut std::io::Cursor<&Vec<u8>>,
    ) -> Result<APISetNamespaceEntry, Box<dyn std::error::Error>> {
        let mut asne = APISetNamespaceEntry::new();

        asne.flags = cursor.read_u32::<LittleEndian>()?;
        asne.name_offset = cursor.read_u32::<LittleEndian>()?;
        asne.name_length = cursor.read_u32::<LittleEndian>()?;
        asne.hashed_length = cursor.read_u32::<LittleEndian>()?;
        asne.value_offset = cursor.read_u32::<LittleEndian>()?;
        asne.value_count = cursor.read_u32::<LittleEndian>()?;

        return Ok(asne);
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct APISetValueEntry {
    flags: u32,
    name_offset: u32,
    name_length: u32,
    value_offset: u32,
    value_length: u32,
}

impl APISetValueEntry {
    pub fn new() -> APISetValueEntry {
        return APISetValueEntry::default();
    }

    pub fn from_parser(
        cursor: &mut std::io::Cursor<&Vec<u8>>,
    ) -> Result<APISetValueEntry, Box<dyn std::error::Error>> {
        let mut asve = APISetValueEntry::new();

        asve.flags = cursor.read_u32::<LittleEndian>()?;
        asve.name_offset = cursor.read_u32::<LittleEndian>()?;
        asve.name_length = cursor.read_u32::<LittleEndian>()?;
        asve.value_offset = cursor.read_u32::<LittleEndian>()?;
        asve.value_length = cursor.read_u32::<LittleEndian>()?;

        return Ok(asve);
    }
}

#[derive(Default, Clone, Debug)]
pub struct APISet {
    mapping: HashMap<String, String>,
}

impl APISet {
    pub fn new() -> APISet {
        return APISet::default();
    }

    pub fn map(&self, dll_name: &String) -> Option<&String> {
        return self.mapping.get(dll_name);
    }
}

fn parse_apiset(apiset_dll: super::pe::PE) -> Result<APISet, Box<dyn std::error::Error>> {
    let mut apiset: APISet = APISet::new();

    let apiset_section = apiset_dll
        .sections
        .get(".apiset")
        .expect("Cannot find .apiset section in apiset dll");

    let mut cursor = std::io::Cursor::new(&apiset_dll.data);

    let section_start = apiset_section.header.ptr_to_raw_data as u64;

    cursor.set_position(section_start);

    let asn = APISetNamespace::from_parser(&mut cursor)?;

    cursor.set_position(section_start + asn.entry_offset as u64);

    for _ in 0..asn.count {
        let cursor_position = cursor.position();
        let asne = APISetNamespaceEntry::from_parser(&mut cursor)?;
        let mut name_buffer: Vec<u8> = vec![0; asne.name_length as usize];

        cursor.set_position(section_start + asne.name_offset as u64);
        cursor.read_exact(name_buffer.as_mut())?;

        let (front, slice, back) = unsafe { name_buffer.as_slice().align_to::<u16>() };

        if !front.is_empty() && !back.is_empty() {
            return Err("Error while trying to read name of APISetNamespaceEntry".into());
        }

        let api_set_name = String::from_utf16(slice).expect("Invalid utf-16 name");

        if asne.value_count > 0 {
            cursor.set_position(section_start + asne.value_offset as u64);

            let asve = APISetValueEntry::from_parser(&mut cursor)?;

            let mut value_buffer: Vec<u8> = vec![0; asve.value_length as usize];
            cursor.set_position(section_start + asve.value_offset as u64);
            cursor.read_exact(&mut value_buffer)?;

            let (front, slice, back) = unsafe { value_buffer.as_slice().align_to::<u16>() };

            if !front.is_empty() && !back.is_empty() {
                return Err("Error while trying to read name of APISetNamespaceEntry".into());
            }

            let host_dll_name = String::from_utf16(slice).expect("Invalid utf-16 name");

            apiset.mapping.insert(
                api_set_name.trim_end_matches('\0').to_ascii_lowercase(),
                host_dll_name.trim_end_matches('\0').to_ascii_lowercase(),
            );
        }

        cursor.set_position(cursor_position + std::mem::size_of::<APISetNamespaceEntry>() as u64);
    }

    return Ok(apiset);
}

pub fn load_apisetschema_mapping() -> Result<APISet, Box<dyn std::error::Error>> {
    let pe = super::pe::parse_pe(APISetSchemaDLLPath)?;

    return parse_apiset(pe);
}
