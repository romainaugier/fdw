use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::io;
use std::io::Read;

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
 * Image Data Directory (Last 16 members of the Optional Header)
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImageDataDirectory {
    virtual_address: u32,
    size: u32,
}

impl ImageDataDirectory {
    pub fn new() -> ImageDataDirectory {
        return ImageDataDirectory::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<Vec<u8>>,
    ) -> Result<ImageDataDirectory, Box<dyn std::error::Error>> {
        let mut idd = ImageDataDirectory::new();

        idd.virtual_address = cursor.read_u32::<LittleEndian>()?;
        idd.size = cursor.read_u32::<LittleEndian>()?;

        return Ok(idd);
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
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u32,
    size_of_stack_commit: u32,
    size_of_heap_reserve: u32,
    size_of_heap_commit: u32,
    loader_flags: u32, /* reserved_field */
    number_of_rva_and_sizes: u32,

    /* Data Directories */
    export_table: ImageDataDirectory,
    import_table: ImageDataDirectory,
    resource_table: ImageDataDirectory,
    exception_table: ImageDataDirectory,
    certificate_table: ImageDataDirectory,
    base_relocation_table: ImageDataDirectory,
    debug: ImageDataDirectory,
    architecture: ImageDataDirectory, /* reserved field */
    global_ptr: ImageDataDirectory,
    tls_table: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,
    import_address_table: ImageDataDirectory, /* IAT */
    delay_import_descriptor: ImageDataDirectory,
    clr_runtime_header: ImageDataDirectory,
    zero: ImageDataDirectory, /* reserved field */
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
        header.subsystem = cursor.read_u16::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u32::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u32::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = ImageDataDirectory::from_parser(cursor)?;
        header.import_table = ImageDataDirectory::from_parser(cursor)?;
        header.resource_table = ImageDataDirectory::from_parser(cursor)?;
        header.exception_table = ImageDataDirectory::from_parser(cursor)?;
        header.certificate_table = ImageDataDirectory::from_parser(cursor)?;
        header.base_relocation_table = ImageDataDirectory::from_parser(cursor)?;
        header.debug = ImageDataDirectory::from_parser(cursor)?;
        header.architecture = ImageDataDirectory::from_parser(cursor)?; /* reserved field */
        header.global_ptr = ImageDataDirectory::from_parser(cursor)?;
        header.tls_table = ImageDataDirectory::from_parser(cursor)?;
        header.load_config_table = ImageDataDirectory::from_parser(cursor)?;
        header.bound_import = ImageDataDirectory::from_parser(cursor)?;
        header.import_address_table = ImageDataDirectory::from_parser(cursor)?; /* IAT */
        header.delay_import_descriptor = ImageDataDirectory::from_parser(cursor)?;
        header.clr_runtime_header = ImageDataDirectory::from_parser(cursor)?;
        header.zero = ImageDataDirectory::from_parser(cursor)?; /* reserved field */

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
    subsystem: u16,
    dll_characteristics: u16,
    size_of_stack_reserve: u64,
    size_of_stack_commit: u64,
    size_of_heap_reserve: u64,
    size_of_heap_commit: u64,
    loader_flags: u32, /* reserved_field */
    number_of_rva_and_sizes: u32,

    /* Data Directories */
    export_table: ImageDataDirectory,
    import_table: ImageDataDirectory,
    resource_table: ImageDataDirectory,
    exception_table: ImageDataDirectory,
    certificate_table: ImageDataDirectory,
    base_relocation_table: ImageDataDirectory,
    debug: ImageDataDirectory,
    architecture: ImageDataDirectory, /* reserved field */
    global_ptr: ImageDataDirectory,
    tls_table: ImageDataDirectory,
    load_config_table: ImageDataDirectory,
    bound_import: ImageDataDirectory,
    import_address_table: ImageDataDirectory, /* IAT */
    delay_import_descriptor: ImageDataDirectory,
    clr_runtime_header: ImageDataDirectory,
    zero: ImageDataDirectory, /* reserved field */
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
        header.subsystem = cursor.read_u16::<LittleEndian>()?;
        header.dll_characteristics = cursor.read_u16::<LittleEndian>()?;
        header.size_of_stack_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_stack_commit = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_reserve = cursor.read_u64::<LittleEndian>()?;
        header.size_of_heap_commit = cursor.read_u64::<LittleEndian>()?;
        header.loader_flags = cursor.read_u32::<LittleEndian>()?; /* reserved_field */
        header.number_of_rva_and_sizes = cursor.read_u32::<LittleEndian>()?;
        header.export_table = ImageDataDirectory::from_parser(cursor)?;
        header.import_table = ImageDataDirectory::from_parser(cursor)?;
        header.resource_table = ImageDataDirectory::from_parser(cursor)?;
        header.exception_table = ImageDataDirectory::from_parser(cursor)?;
        header.certificate_table = ImageDataDirectory::from_parser(cursor)?;
        header.base_relocation_table = ImageDataDirectory::from_parser(cursor)?;
        header.debug = ImageDataDirectory::from_parser(cursor)?;
        header.architecture = ImageDataDirectory::from_parser(cursor)?; /* reserved field */
        header.global_ptr = ImageDataDirectory::from_parser(cursor)?;
        header.tls_table = ImageDataDirectory::from_parser(cursor)?;
        header.load_config_table = ImageDataDirectory::from_parser(cursor)?;
        header.bound_import = ImageDataDirectory::from_parser(cursor)?;
        header.import_address_table = ImageDataDirectory::from_parser(cursor)?; /* IAT */
        header.delay_import_descriptor = ImageDataDirectory::from_parser(cursor)?;
        header.clr_runtime_header = ImageDataDirectory::from_parser(cursor)?;
        header.zero = ImageDataDirectory::from_parser(cursor)?; /* reserved field */

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

enum SectionFlag {
    IMAGE_SCN_CNT_RES_0 = 0x00000000,   //Reserved for future use.
    IMAGE_SCN_CNT_RES_1 = 0x00000001,   // Reserved for future use.
    IMAGE_SCN_CNT_RES_2 = 0x00000002,   // Reserved for future use.
    IMAGE_SCN_CNT_RES_4 = 0x00000004,   // Reserved for future use.
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008, // The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
    IMAGE_SCN_CNT_RES_10 = 0x00000010,  //Reserved for future use.
    IMAGE_SCN_CNT_CODE = 0x00000020,    // The section contains executable code.
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040, // The section contains initialized data.
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080, // The section contains uninitialized data.
    IMAGE_SCN_LNK_OTHER = 0x00000100,   // Reserved for future use.
    IMAGE_SCN_LNK_INFO = 0x00000200, // The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
    IMAGE_SCN_CNT_RES_1024 = 0x00000400, //Reserved for future use.
    IMAGE_SCN_LNK_REMOVE = 0x00000800, // The section will not become part of the image. This is valid only for object files.
    IMAGE_SCN_LNK_COMDAT = 0x00001000, // The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
    IMAGE_SCN_GPREL = 0x00008000, // The section contains data referenced through the global pointer (GP).
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000, // Reserved for future use.
    // IMAGE_SCN_MEM_16BIT = 0x00020000, // Reserved for future use.
    IMAGE_SCN_MEM_LOCKED = 0x00040000,   // Reserved for future use.
    IMAGE_SCN_MEM_PRELOAD = 0x00080000,  // Reserved for future use.
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000, // Align data on a 1-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000, // Align data on a 2-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000, // Align data on a 4-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000, // Align data on an 8-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000, // Align data on a 16-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000, // Align data on a 32-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000, // Align data on a 64-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000, // Align data on a 128-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000, // Align data on a 256-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000, // Align data on a 512-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000, // Align data on a 1024-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000, // Align data on a 2048-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000, // Align data on a 4096-byte boundary. Valid only for object files.
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000, // Align data on an 8192-byte boundary. Valid only for object files.
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000, // The section contains extended relocations.
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000, // The section can be discarded as needed.
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,  // The section cannot be cached.
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,   // The section is not pageable.
    IMAGE_SCN_MEM_SHARED = 0x10000000,      // The section can be shared in memory.
    IMAGE_SCN_MEM_EXECUTE = 0x20000000,     // The section can be executed as code.
    IMAGE_SCN_MEM_READ = 0x40000000,        // The section can be read.
    IMAGE_SCN_MEM_WRITE = 0x80000000,       // The section can be written to.
}

/*
* Typical segment names:
* .text: Code
* .data: Initialized data
* .bss: Uninitialized data
* .rdata: Const/read-only (and initialized) data
* .edata: Export descriptors
* .idata: Import descriptors
* .pdata: Exception information
* .xdata: Stack unwinding information
* .reloc: Relocation table (for code instructions with absolute addressing when the module could not be loaded at its preferred base address)
* .rsrc: Resources (icon, bitmap, dialog, ...)
* .tls: __declspec(thread) data
*/

#[derive(Default, Clone)]
#[repr(C)]
pub struct Section {
    header: SectionHeader,
    raw_data: Vec<u8>,
}

impl std::fmt::Debug for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return f
            .debug_struct("Section")
            .field("header", &self.header)
            .finish();
    }
}

impl Section {
    pub fn new(header: SectionHeader, raw_data: Vec<u8>) -> Section {
        return Section {
            header: header,
            raw_data: raw_data,
        };
    }
}

/*
 * Image Import Descriptor (struct found in the Import Table (IDT))
 */

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImageImportDescriptor {
    import_lookup_table_rva: u32,
    time_date_stamp: u32,
    forwarder_chain: u32,
    name_rva: u32,
    import_address_table_rva: u32,
}

impl ImageImportDescriptor {
    pub fn new() -> ImageImportDescriptor {
        return ImageImportDescriptor::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<Vec<u8>>,
    ) -> Result<ImageImportDescriptor, Box<dyn std::error::Error>> {
        let mut descriptor = ImageImportDescriptor::new();

        descriptor.import_lookup_table_rva = cursor.read_u32::<LittleEndian>()?;
        descriptor.time_date_stamp = cursor.read_u32::<LittleEndian>()?;
        descriptor.forwarder_chain = cursor.read_u32::<LittleEndian>()?;
        descriptor.name_rva = cursor.read_u32::<LittleEndian>()?;
        descriptor.import_address_table_rva = cursor.read_u32::<LittleEndian>()?;

        return Ok(descriptor);
    }

    pub fn is_zeroed_out(&self) -> bool {
        return self.import_lookup_table_rva == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.import_address_table_rva == 0;
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct ImportLookupEntry {
    by_ordinal: bool,
    ordinal_number: u16,
    hint_name_table_rva: u32,
}

impl ImportLookupEntry {
    pub fn new() -> ImportLookupEntry {
        return ImportLookupEntry::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<Vec<u8>>,
        is_32_bits: bool,
    ) -> Result<ImportLookupEntry, Box<dyn std::error::Error>> {
        let mut entry = ImportLookupEntry::new();

        if is_32_bits {
            let data = cursor.read_u32::<LittleEndian>()?;
            entry.by_ordinal = (data & 0x80000000) > 0;

            if entry.by_ordinal {
                entry.ordinal_number = (data & 0xFFFF) as u16;
            } else {
                entry.hint_name_table_rva = (data & 0x7FFFFFF) as u32;
            }
        } else {
            let data = cursor.read_u64::<LittleEndian>()?;
            entry.by_ordinal = (data & 0x8000000000000000) > 0;

            if entry.by_ordinal {
                entry.ordinal_number = (data & 0xFFFF) as u16;
            } else {
                entry.hint_name_table_rva = (data & 0x7FFFFFF) as u32;
            }
        }

        return Ok(entry);
    }
}

#[derive(Default, Clone, Debug)]
#[repr(C)]
pub struct HintNameEntry {
    hint: u16,
    name: String,
    pad: bool,
}

impl HintNameEntry {
    pub fn new() -> HintNameEntry {
        return HintNameEntry::default();
    }

    pub fn from_parser(
        cursor: &mut io::Cursor<Vec<u8>>,
    ) -> Result<HintNameEntry, Box<dyn std::error::Error>> {
        let mut entry = HintNameEntry::new();

        entry.hint = cursor.read_u16::<LittleEndian>()?;

        let mut name_buffer: Vec<u8> = Vec::new();

        loop {
            let c = cursor.read_u8()?;

            if c == 0x0 {
                break;
            }

            name_buffer.push(c);
        }

        if (name_buffer.len() % 2) != 0 {
            cursor.read_u8()?;
            entry.pad = true;
        } else {
            entry.pad = false;
        }

        entry.name = String::from_utf8(name_buffer).expect("Invalid name found in Hint/Name Table");

        return Ok(entry);
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
    sections: HashMap<String, Section>,
    import_descriptors: Vec<ImageImportDescriptor>,
    pub dll_names: Vec<String>,
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

    pub fn is_32_bits(&self) -> bool {
        match &self.header {
            PEHeader::PE32(_) => return true,
            PEHeader::PE64(_) => return false,
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

    pub fn get_import_table_idd(&self) -> ImageDataDirectory {
        match &self.header {
            PEHeader::PE32(header) => {
                return header.optional.import_table.clone();
            }
            PEHeader::PE64(header) => {
                return header.optional.import_table.clone();
            }
        }
    }

    pub fn convert_rva_to_file_offset(&self, rva: u32) -> Option<u64> {
        for section in self.sections.values() {
            let start = section.header.virtual_address;
            let end = start + section.header.virtual_size;

            if rva >= start && rva < end {
                let offset_in_section = (rva - start) as u64;
                return Some(section.header.ptr_to_raw_data as u64 + offset_in_section);
            }
        }

        return None;
    }
}

/*
 * Parse import descriptors
 */
fn parse_import_descriptors(
    pe: &PE,
    cursor: &mut io::Cursor<Vec<u8>>,
) -> Result<Vec<ImageImportDescriptor>, Box<dyn std::error::Error>> {
    let mut descriptors: Vec<ImageImportDescriptor> = Vec::new();

    let import_table_idd = pe.get_import_table_idd();

    let file_offset = pe
        .convert_rva_to_file_offset(import_table_idd.virtual_address)
        .ok_or("Import Table RVA does not map to any section")?;

    cursor.set_position(file_offset as u64);

    loop {
        let descriptor = ImageImportDescriptor::from_parser(cursor)
            .expect("Cannot parse ImageImportDescriptor from the Import Table");

        if descriptor.is_zeroed_out() {
            break;
        }

        descriptors.push(descriptor);

        if descriptors.len() > 256 {
            break;
        }
    }

    return Ok(descriptors);
}

/*
 * Parse dll names
 */
fn parse_dll_names(
    pe: &PE,
    cursor: &mut io::Cursor<Vec<u8>>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut dlls: Vec<String> = Vec::new();

    for import_descriptor in &pe.import_descriptors {
        cursor.set_position(
            pe.convert_rva_to_file_offset(import_descriptor.name_rva)
                .ok_or("Import Descriptor Name RVA does not map to any section")?,
        );

        let mut name_buffer: Vec<u8> = Vec::new();

        loop {
            let c = cursor.read_u8()?;

            if c == 0x0 {
                break;
            }

            name_buffer.push(c);
        }

        dlls.push(String::from_utf8(name_buffer).expect("Invalid name found in import names"));
    }

    return Ok(dlls);
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
    cursor.set_position(cursor.position() - 2);

    let start_of_optional_position = cursor.position();

    match optional_magic {
        PE_FORMAT_32_MAGIC => {
            let optional_header: OptionalHeader32 = OptionalHeader32::from_parser(&mut cursor)?;

            pe.header = PEHeader::PE32(PE32Header {
                dos: dos_header,
                nt: nt_header,
                optional: optional_header,
            });
        }
        PE_FORMAT_64_MAGIC => {
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

    cursor.set_position(cursor.position() + (pe.get_size_of_optional_header() - optional_size));

    for _ in 0..pe.get_number_of_sections() {
        let section_header = SectionHeader::from_parser(&mut cursor)?;
        let cursor_position_after_section_header = cursor.position();

        let mut section_raw_data = vec![0; section_header.size_of_raw_data as usize];

        cursor.set_position(section_header.ptr_to_raw_data as u64);

        let read_bytes = cursor
            .read(&mut section_raw_data)
            .expect("Could not read raw data from section");

        if read_bytes as u32 != section_header.size_of_raw_data {
            return Err("Could not read all raw data from section".into());
        }

        pe.sections.insert(
            section_header.name.clone(),
            Section {
                header: section_header,
                raw_data: section_raw_data,
            },
        );

        cursor.set_position(cursor_position_after_section_header);
    }

    pe.import_descriptors = parse_import_descriptors(&pe, &mut cursor)?;
    pe.dll_names = parse_dll_names(&pe, &mut cursor)?;

    return Ok(pe);
}
