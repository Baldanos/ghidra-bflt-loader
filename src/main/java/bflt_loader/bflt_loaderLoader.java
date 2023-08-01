/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bflt_loader;

import java.io.InputStream;
import java.io.IOException;


import java.util.*;
import java.util.zip.GZIPInputStream;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.listing.Program;
import ghidra.program.model.data.PointerDataType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
	
import ghidra.program.flatapi.FlatProgramAPI;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.Msg;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class bflt_loaderLoader extends AbstractLibrarySupportLoader {

	@Override
	public String getName() {
		return "bFLT Loader";
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		
        BinaryReader reader = new BinaryReader(provider, true);

		if (reader.readNextAsciiString(4).equals("bFLT")) {
			return List.of(new LoadSpec(this, 0, true));
		}
		return new ArrayList<>();
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		BinaryReader reader = new BinaryReader(provider, true);
		FlatProgramAPI api = new FlatProgramAPI(program, monitor);
		
		reader.setPointerIndex(0);
		BFLTHeader header = new BFLTHeader(reader);
		
		InputStream input;
		
		//Create .text section
		
		//If loading a library, it will be loaded in upper memory, but the code will still be 
		//right after the header
		input = provider.getInputStream(header.entry & 0x00ffffff);
		int text_section_size = header.data_start-(header.entry & 0x00ffffff);
		createSegment(api, input, ".text", api.toAddr(header.entry), text_section_size, true, false, true);
		
		//Create .data section
		// If GZDATA, extract before creating section
		if((header.flags & header.FLAT_FLAG_GZDATA) != 0) {
			input = provider.getInputStream(header.data_start);
			GZIPInputStream gis = new GZIPInputStream(input);
			createSegment(api, gis, ".data", api.toAddr(header.data_start+header.base_address), header.data_end-header.data_start, true, true, false);
		} else {
			input = provider.getInputStream(header.data_start);
			createSegment(api, input, ".data", api.toAddr(header.data_start+header.base_address), header.data_end-header.data_start, true, true, false);
		}
		
		//Create .bss section
		createSegment(api, null, ".bss", api.toAddr(header.data_end+header.base_address), header.bss_end, true, true, false);
		
		// If GOTPIC, patch GOT (see http://www.devttys0.com/2012/03/writing-a-bflt-loader-for-ida/)
		if((header.flags & header.FLAT_FLAG_GOTPIC) != 0) {
			long got_pointer = header.data_start+header.base_address;
			int got_entry = 0;
			
			try {
				got_entry = api.getInt(api.toAddr(got_pointer));
				while( got_entry != 0xffffffff ) {
					
					if(got_entry != 0) {
						got_entry += header.header_size;
						api.setInt(api.toAddr(got_pointer), got_entry);
						if(header.entry <= got_entry && got_entry < (header.entry + text_section_size)) {
							//Points to code
							api.createData(api.toAddr(got_pointer), PointerDataType.dataType);
							api.createFunction(api.toAddr(got_entry), null);
						} else {
							//Points elsewhere
							api.createData(api.toAddr(got_pointer), PointerDataType.dataType);
						}
					}
					got_pointer += 4;
					got_entry = api.getInt(api.toAddr(got_pointer));
				}
			} catch (Exception e) {
				Msg.error(this,  e.getMessage());
			}	
		}
		
		// Perform relocation
		try {
			for (int relocIndex = 0; relocIndex < header.reloc_count; relocIndex++) {
				var beReader = reader.asBigEndian();
				long relocAddress = 0x40 + beReader.readUnsignedInt(header.base_address + header.data_end + 4 * relocIndex);
				// Read the value as big endian, add 0x40 (header size) and then write it in the target architecture's endianness (usually little endian)
				long relocValueBefore = beReader.readUnsignedInt(relocAddress);
				long relocValueAfter = relocValueBefore + 0x40;
				api.setInt(api.toAddr(relocAddress), (int) relocValueAfter);
				// TODO store this as a Relocation in Ghidra DB https://ghidra.re/ghidra_docs/api/ghidra/program/model/reloc/Relocation.html
			}
		} catch (MemoryAccessException e) {
			Msg.error(this, e.getMessage());
		}
		
		api.addEntryPoint(api.toAddr(header.entry));
		api.disassemble(api.toAddr(header.entry));
		api.createFunction(api.toAddr(header.entry), "_entry");
	}
	
	//Taken from https://github.com/NeatMonster/mclf-ghidra-loader/blob/master/src/main/java/mclfloader/MCLFLoader.java
    private void createSegment(FlatProgramAPI api, InputStream input, String name, Address start, long length, boolean read, boolean write, boolean exec) {
        try {
            MemoryBlock block = api.createMemoryBlock(name, start, input, length, false);
            block.setRead(read);
            block.setWrite(write);
            block.setExecute(exec);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }
}
