package bflt_loader;

import java.io.IOException;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;


public class BFLTHeader implements StructConverter {
	public String magic;
	public int version;
	public int entry;
	public int data_start;
	public int data_end;
	public int bss_end;
	public int stack_size;
	public int reloc_start;
	public int reloc_count;
	public int flags;
	public int build_date;
	public int filler[];
	public int base_address;
	
	public int FLAT_FLAG_RAM = 0x1;
	public int FLAT_FLAG_GOTPIC = 0x2;
	public int FLAT_FLAG_GZIP = 0x4;
	public int FLAT_FLAG_GZDATA = 0x8;
	public int FLAT_FLAG_KTRACE = 0x10;
	
	public int header_size = 0x40;
	
		

	public BFLTHeader(BinaryReader reader) throws IOException {
		magic = reader.readNextAsciiString(4);
		if (!magic.equals("bFLT")) {
			throw new UnknownError("Unknown file format: " + magic);
		}
		boolean selected_endian = reader.isLittleEndian();
		reader.setLittleEndian(false);
		
		reader.setPointerIndex(4);
		version = reader.readNextInt();
		entry = reader.readNextInt();
		// Libraries are loaded at higher addresses
		base_address = entry & 0xff000000;
		data_start = reader.readNextInt();
		data_end = reader.readNextInt();
		bss_end = reader.readNextInt();
		stack_size = reader.readNextInt();
		reloc_start = reader.readNextInt();
		reloc_count = reader.readNextInt();
		flags = reader.readNextInt();
		
		reader.setLittleEndian(selected_endian);
	}
	
	public DataType toDataType() {
		Structure struct = new StructureDataType("BFLTHeader_t", 0);
		struct.add(ASCII, 4, "magic", null);
		struct.add(DWORD, 1, "version", null);
		struct.add(DWORD, 1, "entry", null);
		struct.add(DWORD, 4, "data_start", null);
		struct.add(DWORD, 2, "data_end", null);
		struct.add(DWORD, 2, "bss_end", null);
		struct.add(DWORD, 4, "stack_size", null);
		struct.add(DWORD, 4, "reloc_start", null);
		struct.add(DWORD, 4, "reloc_count", null);
		struct.add(DWORD, 4, "flags", null);
		struct.add(DWORD, 4, "build_date", null);
		struct.add(BYTE, 5, "filler", null);
		return struct;
	}
}