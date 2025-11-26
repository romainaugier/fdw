use byteorder::{LittleEndian, ReadBytesExt};
use std::error::Error;
use std::fs;
use std::io;

/*
 * https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 */

/*
 * MS-DOS Header present in every executable file
 */

/* Magic number for MS-DOS executable */
const DOS_MAGIC: u16 = 0x5a4d;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct DOSHeader {
    magic: u16,  // Magic number
    lfanew: u32, // File address of new exe header
}

impl DOSHeader {
    fn new() -> DOSHeader {
        return DOSHeader::default();
    }

    fn from_parser(cursor: &mut io::Cursor<Vec<u8>>) -> Result<DOSHeader, Box<dyn Error>> {
        let mut header: DOSHeader = DOSHeader::new();
        header.magic = cursor.read_u16::<LittleEndian>()?;

        if header.magic != DOS_MAGIC {
            return Err("Invalid DOS magic number".into());
        }

        cursor.set_position(0x3C);

        header.lfanew = cursor.read_u32::<LittleEndian>()?;

        return Ok(header);
    }
}

/*
 * COFF Header
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct COFFHeader {
    machine: u16,
    number_of_sections: u16,
    time_date_stamp: u32,
    pointer_to_symbol_table: u32,
    number_of_symbols: u32,
    size_of_optional_header: u16,
    characteristics: u16,
}

impl COFFHeader {
    fn new() -> COFFHeader {
        return COFFHeader::default();
    }

    fn from_parser(cursor: &mut io::Cursor<Vec<u8>>) -> Result<COFFHeader, Box<dyn Error>> {
        let mut header: COFFHeader = COFFHeader::default();

        header.machine = cursor.read_u16::<LittleEndian>()?;
        header.number_of_sections = cursor.read_u16::<LittleEndian>()?;
        header.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_symbol_table = cursor.read_u32::<LittleEndian>()?;
        header.number_of_symbols = cursor.read_u32::<LittleEndian>()?;
        header.size_of_optional_header = cursor.read_u16::<LittleEndian>()?;
        header.characteristics = cursor.read_u16::<LittleEndian>()?;

        return Ok(header);
    }
}

const NT_PE_SIGNATURE: u32 = 0x4550;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct NTHeader {
    signature: u32,
    coff_header: COFFHeader,
}

impl NTHeader {
    fn new() -> NTHeader {
        return NTHeader::default();
    }

    fn from_parser(cursor: &mut io::Cursor<Vec<u8>>) -> Result<NTHeader, Box<dyn Error>> {
        let mut header: NTHeader = NTHeader::default();
        header.signature = cursor.read_u32::<LittleEndian>()?;

        if header.signature != NT_PE_SIGNATURE {
            return Err("Invalid PE signature in NT Header".into());
        }

        header.coff_header = COFFHeader::from_parser(cursor)?;

        return Ok(header);
    }
}

/*
 * Optional Header for 32/32+ images
 */

/* Magic number for 32 bits PE */
const PE_FORMAT_32_MAGIC: u16 = 0x10b;

/* Magic number for 64 bits PE (PE32+ in the doc) */
const PE_FORMAT_64_MAGIC: u16 = 0x20b;

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionalHeader32 {
    /* Standard Fields */
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,
    base_of_data: u32,

    /* Windows Specific Fields */
    image_base: u32,
    section_alignment: u32,
    file_alignement: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32, /* reserved field */
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32, /* reserved_field */
    number_of_rva_and_sizes: u32,

    /* Data Directories */
    export_table: u64,
    import_table: u64,
    resource_table: u64,
    exception_table: u64,
    certificate_table: u64,
    base_relocation_table: u64,
    debug: u64,
    architecture: u64, /* reserved field */
    global_ptr: u64,
    tls_table: u64,
    load_config_table: u64,
    bound_import: u64,
    import_address_table: u64, /* IAT */
    delay_import_descriptor: u64,
    clr_runtime_header: u64,
    zero: u64, /* reserved field */
}

impl OptionalHeader32 {
    fn new() -> OptionalHeader32 {
        return OptionalHeader32::default();
    }

    fn from_parser(cursor: &mut io::Cursor<Vec<u8>>) -> Result<OptionalHeader32, Box<dyn Error>> {
        let mut header: OptionalHeader32 = OptionalHeader32::new();

        header.magic = cursor.read_u16::<LittleEndian>()?;
        header.major_linker_version = cursor.read_u8()?;
        header.minor_linker_version = cursor.read_u8()?;
        header.size_of_code = cursor.read_u32::<LittleEndian>()?;
        header.size_of_initialized_data = cursor.read_u32::<LittleEndian>()?;
        header.size_of_uninitialized_data = cursor.read_u32::<LittleEndian>()?;
        header.address_of_entry_point = cursor.read_u32::<LittleEndian>()?;
        header.base_of_code = cursor.read_u32::<LittleEndian>()?;
        header.base_of_data = cursor.read_u32::<LittleEndian>()?;
        header.image_base = cursor.read_u32::<LittleEndian>()?;
        header.section_alignment = cursor.read_u32::<LittleEndian>()?;
        header.file_alignement = cursor.read_u32::<LittleEndian>()?;
        header.major_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.major_image_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_image_version = cursor.read_u16::<LittleEndian>()?;
        header.major_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.win32_version_value = cursor.read_u32::<LittleEndian>()?; /* reserved field */
        header.size_of_image = cursor.read_u32::<LittleEndian>()?;
        header.size_of_headers = cursor.read_u32::<LittleEndian>()?;
        header.checksum = cursor.read_u32::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u32::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = cursor.read_u64::<LittleEndian>()?;
        header.import_table = cursor.read_u64::<LittleEndian>()?;
        header.resource_table = cursor.read_u64::<LittleEndian>()?;
        header.exception_table = cursor.read_u64::<LittleEndian>()?;
        header.certificate_table = cursor.read_u64::<LittleEndian>()?;
        header.base_relocation_table = cursor.read_u64::<LittleEndian>()?;
        header.debug = cursor.read_u64::<LittleEndian>()?;
        header.architecture = cursor.read_u64::<LittleEndian>()?; /* reserved field */
        header.global_ptr = cursor.read_u64::<LittleEndian>()?;
        header.tls_table = cursor.read_u64::<LittleEndian>()?;
        header.load_config_table = cursor.read_u64::<LittleEndian>()?;
        header.bound_import = cursor.read_u64::<LittleEndian>()?;
        header.import_address_table = cursor.read_u64::<LittleEndian>()?; /* IAT */
        header.delay_import_descriptor = cursor.read_u64::<LittleEndian>()?;
        header.clr_runtime_header = cursor.read_u64::<LittleEndian>()?;
        header.zero = cursor.read_u64::<LittleEndian>()?; /* reserved field */

        return Ok(header);
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct OptionalHeader64 {
    /* Standard Fieds */
    magic: u16,
    major_linker_version: u8,
    minor_linker_version: u8,
    size_of_code: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
    address_of_entry_point: u32,
    base_of_code: u32,

    /* Windows Specific Fields */
    image_base: u64,
    section_alignment: u32,
    file_alignement: u32,
    major_operating_system_version: u16,
    minor_operating_system_version: u16,
    major_image_version: u16,
    minor_image_version: u16,
    major_subsystem_version: u16,
    minor_subsystem_version: u16,
    win32_version_value: u32, /* reserved field */
    size_of_image: u32,
    size_of_headers: u32,
    checksum: u32,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32, /* reserved_field */
    number_of_rva_and_sizes: u32,

    /* Data Directories */
    export_table: u64,
    import_table: u64,
    resource_table: u64,
    exception_table: u64,
    certificate_table: u64,
    base_relocation_table: u64,
    debug: u64,
    architecture: u64, /* reserved field */
    global_ptr: u64,
    tls_table: u64,
    load_config_table: u64,
    bound_import: u64,
    import_address_table: u64, /* IAT */
    delay_import_descriptor: u64,
    clr_runtime_header: u64,
    zero: u64, /* reserved field */
}

impl OptionalHeader64 {
    fn new() -> OptionalHeader64 {
        return OptionalHeader64::default();
    }

    fn from_parser(cursor: &mut io::Cursor<Vec<u8>>) -> Result<OptionalHeader64, Box<dyn Error>> {
        let mut header: OptionalHeader64 = OptionalHeader64::new();

        header.magic = cursor.read_u16::<LittleEndian>()?;
        header.major_linker_version = cursor.read_u8()?;
        header.minor_linker_version = cursor.read_u8()?;
        header.size_of_code = cursor.read_u32::<LittleEndian>()?;
        header.size_of_initialized_data = cursor.read_u32::<LittleEndian>()?;
        header.size_of_uninitialized_data = cursor.read_u32::<LittleEndian>()?;
        header.address_of_entry_point = cursor.read_u32::<LittleEndian>()?;
        header.base_of_code = cursor.read_u32::<LittleEndian>()?;
        header.image_base = cursor.read_u64::<LittleEndian>()?;
        header.section_alignment = cursor.read_u32::<LittleEndian>()?;
        header.file_alignement = cursor.read_u32::<LittleEndian>()?;
        header.major_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_operating_system_version = cursor.read_u16::<LittleEndian>()?;
        header.major_image_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_image_version = cursor.read_u16::<LittleEndian>()?;
        header.major_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.minor_subsystem_version = cursor.read_u16::<LittleEndian>()?;
        header.win32_version_value = cursor.read_u32::<LittleEndian>()?; /* reserved field */
        header.size_of_image = cursor.read_u32::<LittleEndian>()?;
        header.size_of_headers = cursor.read_u32::<LittleEndian>()?;
        header.checksum = cursor.read_u32::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u64::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = cursor.read_u64::<LittleEndian>()?;
        header.import_table = cursor.read_u64::<LittleEndian>()?;
        header.resource_table = cursor.read_u64::<LittleEndian>()?;
        header.exception_table = cursor.read_u64::<LittleEndian>()?;
        header.certificate_table = cursor.read_u64::<LittleEndian>()?;
        header.base_relocation_table = cursor.read_u64::<LittleEndian>()?;
        header.debug = cursor.read_u64::<LittleEndian>()?;
        header.architecture = cursor.read_u64::<LittleEndian>()?; /* reserved field */
        header.global_ptr = cursor.read_u64::<LittleEndian>()?;
        header.tls_table = cursor.read_u64::<LittleEndian>()?;
        header.load_config_table = cursor.read_u64::<LittleEndian>()?;
        header.bound_import = cursor.read_u64::<LittleEndian>()?;
        header.import_address_table = cursor.read_u64::<LittleEndian>()?; /* IAT */
        header.delay_import_descriptor = cursor.read_u64::<LittleEndian>()?;
        header.clr_runtime_header = cursor.read_u64::<LittleEndian>()?;
        header.zero = cursor.read_u64::<LittleEndian>()?; /* reserved field */

        return Ok(header);
    }
}

/*
 * Section
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct SectionHeader {
    name: String,
    virtual_size: u32,
    virtual_address: u32,
    size_of_raw_data: u32,
    ptr_to_raw_data: u32,
    pointer_to_relocations: u32,
    pointer_to_line_numbers: u32,
    number_of_relocations: u16,
    number_of_line_numbers: u16,
    characteristics: u32,
}

impl SectionHeader {
    fn new() -> SectionHeader {
        return SectionHeader::default();
    }

    fn from_parser(
        cursor: &mut io::Cursor<Vec<u8>>,
    ) -> Result<SectionHeader, Box<dyn std::error::Error>> {
        let mut header = SectionHeader::new();

        let first_name_byte = cursor.read_u8()?;

        if first_name_byte == 0x2F as u8 {
            // "/"
            todo!("Need to implement section header name finding in string table");
        } else if first_name_byte == 0x0 as u8 {
            // "\0"
            header.name = "empty".to_string();
            cursor.set_position(cursor.position() + 39);

            return Ok(header);
        } else {
            let mut name_buffer: Vec<u8> = Vec::new();

            name_buffer.push(first_name_byte);

            for _ in 0..7 {
                let c = cursor.read_u8()?;

                if c == '\0' as u8 {
                    continue;
                }

                name_buffer.push(c);
            }

            println!("name: {:?}", name_buffer);

            header.name = String::from_utf8(name_buffer).expect("Invalid section name found in PE");
        }

        header.virtual_size = cursor.read_u32::<LittleEndian>()?;
        header.virtual_address = cursor.read_u32::<LittleEndian>()?;
        header.size_of_raw_data = cursor.read_u32::<LittleEndian>()?;
        header.ptr_to_raw_data = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_relocations = cursor.read_u32::<LittleEndian>()?;
        header.pointer_to_line_numbers = cursor.read_u32::<LittleEndian>()?;
        header.number_of_relocations = cursor.read_u16::<LittleEndian>()?;
        header.number_of_line_numbers = cursor.read_u16::<LittleEndian>()?;
        header.characteristics = cursor.read_u32::<LittleEndian>()?;

        return Ok(header);
    }
}

/*
 * PE Header
 */

#[derive(Default, Clone, Debug)]
pub struct PE32Header {
    dos: DOSHeader,
    nt: NTHeader,
    optional: OptionalHeader32,
}

#[derive(Default, Clone, Debug)]
pub struct PE64Header {
    dos: DOSHeader,
    nt: NTHeader,
    optional: OptionalHeader64,
}

#[derive(Clone, Debug)]
pub enum PEHeader {
    PE32(PE32Header),
    PE64(PE64Header),
}

impl Default for PEHeader {
    fn default() -> PEHeader {
        return PEHeader::PE32(PE32Header::default());
    }
}

/*
 * PE
 */

pub enum PEArchitecture {
    PE32,
    PE64,
}

#[derive(Default, Debug)]
pub struct PE {
    header: PEHeader,
    sections_headers: Vec<SectionHeader>,
}

impl PE {
    pub fn new() -> PE {
        return PE::default();
    }

    pub fn get_architecture(&self) -> PEArchitecture {
        match &self.header {
            PEHeader::PE32(_) => return PEArchitecture::PE32,
            PEHeader::PE64(_) => return PEArchitecture::PE64,
        }
    }

    pub fn get_size_of_optional_header(&self) -> u64 {
        match &self.header {
            PEHeader::PE32(header) => {
                return header.nt.coff_header.size_of_optional_header as u64;
            }
            PEHeader::PE64(header) => {
                return header.nt.coff_header.size_of_optional_header as u64;
            }
        }
    }

    pub fn get_number_of_sections(&self) -> usize {
        match &self.header {
            PEHeader::PE32(header) => {
                return header.nt.coff_header.number_of_sections as usize;
            }
            PEHeader::PE64(header) => {
                return header.nt.coff_header.number_of_sections as usize;
            }
        }
    }
}

/*
 * Main parse method that reads from a file, tests if it's a PE file or not, and returns the parsed PE
 */
pub fn parse_pe(file_path: &str) -> Result<PE, Box<dyn std::error::Error>> {
    let exists = fs::exists(file_path)?;

    if !exists {
        return Err("File does not exist".into());
    }

    if !file_path.ends_with(".exe") {
        return Err("File is not an executable (.exe)".into());
    }

    let file_bytes = std::fs::read(file_path).expect("Unable to open file");

    let mut cursor = io::Cursor::new(file_bytes);

    let dos_header = DOSHeader::from_parser(&mut cursor)?;

    cursor.set_position(dos_header.lfanew as u64);

    let nt_header = NTHeader::from_parser(&mut cursor)?;
    let mut pe: PE = PE::new();

    let optional_magic: u16 = cursor.read_u16::<LittleEndian>()?;

    let start_of_optional_position = cursor.position();

    match optional_magic {
        PE_FORMAT_32_MAGIC => {
            cursor.set_position(cursor.position() - 2);
            let optional_header: OptionalHeader32 = OptionalHeader32::from_parser(&mut cursor)?;

            pe.header = PEHeader::PE32(PE32Header {
                dos: dos_header,
                nt: nt_header,
                optional: optional_header,
            });
        }
        PE_FORMAT_64_MAGIC => {
            cursor.set_position(cursor.position() - 2);
            let optional_header: OptionalHeader64 = OptionalHeader64::from_parser(&mut cursor)?;

            pe.header = PEHeader::PE64(PE64Header {
                dos: dos_header,
                nt: nt_header,
                optional: optional_header,
            });
        }
        _ => {
            return Err("Invalid PE optional header magic".into());
        }
    }

    let end_of_optional_position = cursor.position();
    let optional_size = end_of_optional_position - start_of_optional_position;

    println!("PE Headers: {:?}", pe.header);

    cursor.set_position(cursor.position() + (pe.get_size_of_optional_header() - optional_size - 2));

    for _ in 0..pe.get_number_of_sections() {
        pe.sections_headers
            .push(SectionHeader::from_parser(&mut cursor)?);
    }

    println!("PE Section Headers: {:?}", pe.sections_headers);

    return Ok(pe);
}
