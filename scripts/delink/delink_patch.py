"""Patch ghidra-delinker-extension 0.9.2: exports that cost O(the exported set), and the image-base-relative
relocation kind (IMAGE_REL_AMD64_ADDR32NB) that x64 PE code and data need.

Why, part 1 (2026-10-29, P2b): on the whole-binary delink DB (12 M instructions disassembled, millions of labels, ~2 M
synthesized relocations) the exporter's helpers made every export walk the whole program: `getSectionSymbols` /
`getExternalSymbols` streamed `SymbolTable.getAllSymbols(true)` (4.7 min per module), the relocation table's range
iterator stepped key by key through every gap of a scattered set (a unity unit's contributions lie all over .text),
and `getOffsetWithinAddressSet` built an intersection set per relocation (O(ranges) each, O(ranges x relocations)
per section). The patched versions walk the set range by range (symbols and reference destinations per range, their
aliases through `getSymbols(address)`; the table's submaps per range; a cached prefix-sum index of the set's ranges)
and the "buffer does not contain relocation" error names the address. Semantics are the originals'.

Why, part 2 (2026-10-30, P2c): the extension knows absolute and PC-relative relocations only. An x64 PE holds
32-bit image-base-relative fields (RVAs): every .pdata entry, the UNWIND_INFO handlers and the MSVC exception
tables in .xdata, RTTI and throw-info objects in .rdata, and the switch jump tables inside .text (`mov r32,
[__ImageBase + idx*4 + imagerel table]`). Ghidra types such a field as ImageBaseOffset32 (a pointer typedef, so the
absolute data synthesizer made a 4-byte RelocationAbsolute of it - which the x86-64 COFF builder then dropped: its
`bitmask == 0xffffffff` compares a long with the int -1, never true; a delinked object thus had no .pdata
relocation at all). Now: a new ImageBaseRelativeDataRelocationSynthesizer makes a RelocationRelativeSymbol against
`__ImageBase` of every ImageBaseOffset32 datum (an End field anchored to its Begin sibling's symbol, as MSVC
relocates RUNTIME_FUNCTION.EndAddress against the function with the length as the addend; an RVA of 0 is no
relocation), the absolute data synthesizer leaves those fields alone, the x86 code synthesizer gets a third sink for
an operand that is the referenced target's RVA, and the x86-64 COFF builder writes a RelocationRelativeSymbol
against `__ImageBase` as IMAGE_REL_AMD64_ADDR32NB. The delink DB must type the fields first (delink_all.py's
`rvadata` stage).

Why, part 3 (2026-10-30, the whole-server re-export): with dynamic symbols external (the folded unwind data one
module defines must resolve from the others), the exporter's duplicate-symbol check met Ghidra's offcut names - the
datum's label plus the field path, repeated across the datum's offsets (`G._padding_` seven times) - and failed 6
engine units. The exporter now appends the address to a dynamic symbol's name unless it ends with it already
(Ghidra's own default labels do): `<label>.<path>@<va>`, the same rule for the defined and the undefined side.
Part 4 (the first link): a symbol the PDB named stays external inside another function's body. Part 5 (the first
successful link): every exported range is padded to 16 bytes (code with 0xCC, data with 0; .pdata stays packed),
because the contributions are packed without the original's alignment padding and a 16-byte constant off its
alignment faults the first movaps; the linked .text was 1 MB short of the original's for the same reason.

Apache-2.0 allows the change; the patched jar lives only in the isolated install under `build/delink/settings`
(git-ignored), the original beside it as `.orig`; this script is the record.

usage: python -I _tools/delink_patch.py [--restore]
"""
import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
JDK = TOOLS / "jdk-21.0.12.1+1" / "bin"
GHIDRA = TOOLS / "ghidra_12.1.4_PUBLIC"
EXT = ROOT / "build" / "delink" / "settings" / "PC-ghidra" / "ghidra_12.1.4_PUBLIC" / "Extensions" / "ghidra-delinker-extension"
JAR = EXT / "lib" / "ghidra-delinker-extension.jar"
SRC = EXT / "lib" / "ghidra-delinker-extension-src.zip"
WORK = ROOT / "build" / "delink" / "patch"

PROGRAM_UTIL = "ghidra/app/util/ProgramUtil.java"
RELOC_TABLE = "ghidra/program/model/relocobj/RelocationTable.java"
X64_BUILDER = "ghidra/app/util/exporter/coff/relocs/X86_64_CoffRelocationTableBuilder.java"
ABS_DATA_SYNTH = "ghidra/app/analyzers/relocations/AbsoluteDataRelocationSynthesizer.java"
X86_CODE_SYNTH = "ghidra/app/analyzers/relocations/X86CodeRelocationSynthesizer.java"
IBO_DATA_SYNTH = "ghidra/app/analyzers/relocations/ImageBaseRelativeDataRelocationSynthesizer.java"
EXPORTER = "ghidra/app/util/exporter/CoffRelocatableObjectExporter.java"

NEW_OFFSET = '''	// ATLAS 2026-10-29 (_tools/delink_patch.py): the offset of an address within a set through a prefix-sum index of
	// the set's ranges, cached for the set last asked about (the exporter asks per section, relocation by relocation);
	// the original built an intersection set per call.
	private static AddressSetView offsetSet;
	private static TreeMap<Address, Long> offsetIndex;

	public static long getOffsetWithinAddressSet(AddressSetView addressSet, Address address) {
		synchronized (ProgramUtil.class) {
			if (addressSet != offsetSet) {
				TreeMap<Address, Long> index = new TreeMap<>();
				long sum = 0;
				for (AddressRange range : addressSet.getAddressRanges()) {
					sum += frontPaddingOf(range);
					index.put(range.getMinAddress(), sum);
					sum += range.getLength() + paddingOf(range);
				}
				offsetSet = addressSet;
				offsetIndex = index;
			}
			Map.Entry<Address, Long> entry = offsetIndex.floorEntry(address);
			if (entry == null) {
				throw new IllegalArgumentException("address " + address + " lies before the set");
			}
			return entry.getValue() + address.subtract(entry.getKey());
		}
	}

	// ATLAS 2026-10-30 (part 5): every range of an exported set is placed at an offset congruent to its original
	// address modulo 16 (a front padding of start mod 16) and padded to 16 bytes at its end (code with 0xCC, data
	// with 0), so that every item keeps the alignment the linker gave it - the contributions are packed without
	// the original's padding, adjacent ones merge into one range, and a range beginning at a 4-aligned item carried
	// the 16-byte constants behind it off their alignment: the first movaps faulted; .pdata stays packed (12-byte
	// entries). The exporter sets paddingProgram before it exports.
	public static Program paddingProgram;

	private static boolean padded(AddressRange range) {
		if (paddingProgram == null) {
			return false;
		}
		MemoryBlock block = paddingProgram.getMemory().getBlock(range.getMinAddress());
		return block != null && !block.getName().equals(".pdata");
	}

	public static int frontPaddingOf(AddressRange range) {
		return padded(range) ? (int) (range.getMinAddress().getOffset() % 16) : 0;
	}

	public static int paddingOf(AddressRange range) {
		if (!padded(range)) {
			return 0;
		}
		return (int) ((16 - ((frontPaddingOf(range) + range.getLength()) % 16)) % 16);
	}

	public static long getPaddedSize(AddressSetView addressSet) {
		long sum = 0;
		for (AddressRange range : addressSet.getAddressRanges()) {
			sum += frontPaddingOf(range) + range.getLength() + paddingOf(range);
		}
		return sum;
	}
'''

NEW_GET_BYTES = '''	public static byte[] getBytes(Program program, AddressSetView addressSet)
			throws MemoryAccessException {
		// ATLAS 2026-10-30 (part 5): the ranges concatenated with their padding to 16 bytes (paddingOf)
		MemoryBlock memoryBlock = program.getMemory().getBlock(addressSet.getMinAddress());
		byte[] bytes = new byte[(int) getPaddedSize(addressSet)];
		byte fill = (byte) (memoryBlock != null && memoryBlock.isExecute() ? 0xCC : 0x00);
		int offset = 0;

		for (AddressRange range : addressSet.getAddressRanges()) {
			int front = frontPaddingOf(range);
			for (int i = 0; i < front; i++) {
				bytes[offset + i] = fill;
			}
			offset += front;
			int length = (int) range.getLength();
			memoryBlock.getBytes(range.getMinAddress(), bytes, offset, length);
			offset += length;
			int pad = paddingOf(range);
			for (int i = 0; i < pad; i++) {
				bytes[offset + i] = fill;
			}
			offset += pad;
		}

		return bytes;
	}
'''

NEW_SECTION = '''	public static Map<Address, SymbolInformation> getSectionSymbols(Program program,
			AddressSetView sectionSet, SymbolPreference symbolNamePreference) {
		// ATLAS 2026-10-29 (_tools/delink_patch.py): the symbols inside the set, range by range (the original
		// streamed every symbol of the program, dynamic labels included, once per export; an iterator over a
		// scattered set walks everything between its first and last address). Referenced addresses without a
		// stored symbol carry a dynamic one, which getSymbols(address) makes.
		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager referenceManager = program.getReferenceManager();
		List<Symbol> symbols = new ArrayList<>();
		Set<Address> seen = new HashSet<>();
		for (AddressRange range : sectionSet.getAddressRanges()) {
			Address max = range.getMaxAddress();
			SymbolIterator it = symbolTable.getSymbolIterator(range.getMinAddress(), true);
			while (it.hasNext()) {
				Address a = it.next().getAddress();
				if (a.compareTo(max) > 0) {
					break;
				}
				if (seen.add(a)) {
					for (Symbol s : symbolTable.getSymbols(a)) {
						symbols.add(s);
					}
				}
			}
			AddressIterator ai = referenceManager.getReferenceDestinationIterator(range.getMinAddress(), true);
			while (ai.hasNext()) {
				Address a = ai.next();
				if (a.compareTo(max) > 0) {
					break;
				}
				if (seen.add(a)) {
					for (Symbol s : symbolTable.getSymbols(a)) {
						symbols.add(s);
					}
				}
			}
		}
		return symbols.stream().collect(new SymbolInformationCollector(symbolNamePreference));
	}
'''

NEW_EXTERNAL = '''	public static Map<Address, SymbolInformation> getExternalSymbols(Program program,
			AddressSetView fileSet, SymbolPreference symbolNamePreference) {
		// ATLAS 2026-10-29 (_tools/delink_patch.py): the relocations of the set and the symbols at their targets,
		// not every relocation and every symbol of the program.
		SymbolTable symbolTable = program.getSymbolTable();
		RelocationTable relocationTable = RelocationTable.get(program);

		Set<Address> externalRelocationTargets = StreamSupport.stream(
			Spliterators.spliteratorUnknownSize(relocationTable.getRelocations(fileSet), 0), false)
				.filter(r -> fileSet.contains(r.getAddress()) && !fileSet.contains(r.getTarget()))
				.map(r -> r.getTarget())
				.collect(Collectors.toSet());

		List<Symbol> symbols = new ArrayList<>();
		for (Address target : externalRelocationTargets) {
			for (Symbol s : symbolTable.getSymbols(target)) {
				symbols.add(s);
			}
		}
		return symbols.stream().collect(new SymbolInformationCollector(symbolNamePreference));
	}
'''

NEW_GET_RELOCATIONS = '''	public Iterator<Relocation> getRelocations(AddressSetView iteratorAddressSet) {
		// ATLAS 2026-10-29 (_tools/delink_patch.py): range by range through the map's submaps; the original stepped
		// key by key through every gap of a scattered set.
		List<Relocation> found = new ArrayList<>();
		synchronized (relocations) {
			for (AddressRange range : iteratorAddressSet.getAddressRanges()) {
				found.addAll(relocations.subMap(range.getMinAddress(), true, range.getMaxAddress(), true).values());
			}
		}
		return found.iterator();
	}
'''

# ---------------------------------------------------------------------------------------------- part 2: ADDR32NB
IBO_DATA_SYNTH_SRC = '''/*
 * ATLAS 2026-10-30 (_tools/delink_patch.py), Apache-2.0 as the extension.
 */
package ghidra.app.analyzers.relocations;

import ghidra.app.analyzers.RelocationTableSynthesizerAnalyzer;
import ghidra.app.analyzers.relocations.synthesizers.DataRelocationSynthesizer;
import ghidra.app.analyzers.relocations.utils.RelocationTarget;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerType;
import ghidra.program.model.data.PointerTypeSettingsDefinition;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.util.task.TaskMonitor;

/**
 * A 32-bit image-base-relative field (Ghidra's ImageBaseOffset32 / IBO32 typedef: PE .pdata entries, UNWIND_INFO
 * handlers, MSVC exception tables, RTTI, x64 switch jump tables) is a relocation relative to the image base
 * symbol - IMAGE_REL_AMD64_ADDR32NB in a COFF object. The absolute data synthesizer leaves these fields to this one.
 */
public class ImageBaseRelativeDataRelocationSynthesizer implements DataRelocationSynthesizer {
	public static final String IMAGE_BASE_SYMBOL = "__ImageBase";

	public static boolean isImageBaseRelative(Data data) {
		DataType dt = data.getDataType();
		if (dt instanceof TypeDef) {
			PointerType type = PointerTypeSettingsDefinition.DEF.getType(dt.getDefaultSettings());
			return type == PointerType.IMAGE_BASE_RELATIVE;
		}
		return false;
	}

	@Override
	public boolean process(RelocationTableSynthesizerAnalyzer analyzer, Data pointer,
			TaskMonitor monitor, MessageLog log) throws MemoryAccessException {
		if (!isImageBaseRelative(pointer) || !pointer.isInitializedMemory()) {
			return true;
		}
		Program program = pointer.getProgram();
		Object value = pointer.getValue();
		if (!(value instanceof Address)) {
			return true;
		}
		Address to = (Address) value;
		if (to.equals(program.getImageBase())) {
			// an RVA of 0 (no unwind action, catch(...), no forward-compat handler): no relocation, the field is 0
			return true;
		}
		// an end-of-range field is relative to its begin sibling's symbol: MSVC relocates RUNTIME_FUNCTION.EndAddress
		// (and a chained UNWIND_INFO's FunctionEndAddress) against the function, the length being the addend
		Address anchor = to;
		long extra = 0;
		String field = pointer.getFieldName();
		Data parent = pointer.getParent();
		if (field != null && parent != null && field.endsWith("EndAddress")) {
			String beginName = field.equals("FunctionEndAddress") ? "FunctionStartAddress" : "BeginAddress";
			Data begin = sibling(parent, beginName);
			if (begin != null && begin.getValue() instanceof Address) {
				anchor = (Address) begin.getValue();
				extra = to.subtract(anchor);
			}
		}
		RelocationTarget target = targetOf(program, anchor);
		if (target == null) {
			log.appendMsg(pointer.getAddressString(false, true),
				"image-base-relative field without a symbol for its target " + to);
			return false;
		}
		RelocationTarget finalTarget = analyzer.getFinalRelocationTarget(target);
		analyzer.getRelocationTable().addRelativeSymbol(pointer.getAddress(), pointer.getLength(),
			finalTarget.getDestination(), finalTarget.getOffset() + extra, IMAGE_BASE_SYMBOL);
		return true;
	}

	private static Data sibling(Data parent, String fieldName) {
		for (int i = 0; i < parent.getNumComponents(); i++) {
			Data component = parent.getComponent(i);
			if (fieldName.equals(component.getFieldName())) {
				return component;
			}
		}
		return null;
	}

	/**
	 * The symbol an address is relative to: the one at its code unit, else the entry of the function around it
	 * (a jump-table case or an IP-to-state boundary inside a function body).
	 */
	public static RelocationTarget targetOf(Program program, Address to) {
		CodeUnit codeUnit = program.getListing().getCodeUnitContaining(to);
		Address address = codeUnit != null ? codeUnit.getMinAddress() : to;
		if (program.getSymbolTable().getPrimarySymbol(address) == null) {
			Function function = program.getFunctionManager().getFunctionContaining(to);
			if (function == null) {
				return null;
			}
			address = function.getEntryPoint();
		}
		return new RelocationTarget(address, to.subtract(address));
	}

	@Override
	public boolean canAnalyze(Program program) {
		return true;
	}
}
'''

NEW_X64_RELSYM = '''	private void process(CoffRelocationTable relTable, byte[] bytes,
			AddressSetView addressSet, RelocationRelativeSymbol relocation,
			CoffSymbol symbol, MessageLog log) {
		// ATLAS 2026-10-30 (_tools/delink_patch.py): a 32-bit field relative to __ImageBase is an RVA,
		// IMAGE_REL_AMD64_ADDR32NB; the field holds the addend
		DataConverter dc = LittleEndianDataConverter.INSTANCE;
		if (relocation.getWidth() != 4 || relocation.getBitmask() != 0xffffffffL ||
			!ImageBaseRelativeDataRelocationSynthesizer.IMAGE_BASE_SYMBOL.equals(
				relocation.getRelativeSymbolName())) {
			logUnknownRelocation(relTable.getSection(), relocation, log);
			return;
		}

		patchBytes(bytes, addressSet, dc, relocation, relocation.getAddend());
		emit(relTable, addressSet, relocation, CoffRelocationType_amd64.IMAGE_REL_AMD64_ADDR32NB, symbol);
	}

'''

NEW_X86_IBO_SINK = '''	private static class X86InstructionImageBaseRelativeRelocationEmitter
			extends SymbolRelativeInstructionRelocationEmitter {
		// ATLAS 2026-10-30 (_tools/delink_patch.py): a 32-bit operand that is the referenced target's RVA (an x64
		// switch: mov r32, [rBase + rIndex*4 + imagerel table] with rBase = __ImageBase) is image-base-relative,
		// IMAGE_REL_AMD64_ADDR32NB in the object
		public X86InstructionImageBaseRelativeRelocationEmitter(RelocationTableSynthesizerAnalyzer analyzer,
				Function function, Symbol imageBase, EvaluationReporter evaluationReporter,
				TaskMonitor monitor, MessageLog log) {
			super(analyzer, function, imageBase, evaluationReporter, monitor, log);
		}

		@Override
		public Collection<OperandMatcher> getOperandMatchers() {
			return X86InstructionAbsoluteRelocationEmitter.OPERAND_MATCHERS;
		}

		@Override
		public void emit(Instruction instruction, OperandMatch match, RelocationTarget target,
				Reference reference) {
			Address address = instruction.getAddress().add(match.getOffset());
			long addend = reference.getToAddress().getUnsignedOffset() -
				target.getAddress().getUnsignedOffset();

			getRelocationTable().addRelativeSymbol(address, match.getSize(), match.getBitmask(),
				target.getDestination(), addend, ImageBaseRelativeDataRelocationSynthesizer.IMAGE_BASE_SYMBOL);
		}
	}

'''

NEW_X86_SINKS = '''		var absolute = new X86InstructionAbsoluteRelocationEmitter(analyzer, function,
			evaluationReporter, monitor, log);
		var relative = new X86InstructionRelativeRelocationEmitter(analyzer, function,
			evaluationReporter, monitor, log);

		// ATLAS 2026-10-30: the image-base-relative sink, when the program has an image base symbol (x64 PE)
		Program program = analyzer.getProgram();
		Symbol imageBase = program.getSymbolTable().getPrimarySymbol(program.getImageBase());
		if (imageBase != null && program.getDefaultPointerSize() == 8) {
			var imageBaseRelative = new X86InstructionImageBaseRelativeRelocationEmitter(analyzer,
				function, imageBase, evaluationReporter, monitor, log);
			return List.of(absolute, relative, imageBaseRelative);
		}

		return List.of(absolute, relative);
'''


def replace_method(src: str, signature: str, new: str) -> str:
    start = src.index(signature)
    end = src.index("\n\t}\n", start) + len("\n\t}\n")
    return src[:start] + new + src[end:]


def add_imports(src: str, after: str, imports: list) -> str:
    assert after in src, after
    return src.replace(after, after + "".join(f"import {i};\n" for i in imports), 1)


def replace_once(src: str, old: str, new: str) -> str:
    assert src.count(old) == 1, old[:80]
    return src.replace(old, new)


def patch_program_util(src: str) -> str:
    assert src.count("getAllSymbols(true)") == 2, "the source is not 0.9.2's (two getAllSymbols(true) expected)"
    src = replace_method(src, "\tpublic static long getOffsetWithinAddressSet(AddressSetView addressSet, Address address) {",
                         NEW_OFFSET)
    src = replace_method(src, "\tpublic static Map<Address, SymbolInformation> getSectionSymbols(", NEW_SECTION)
    src = replace_method(src, "\tpublic static Map<Address, SymbolInformation> getExternalSymbols(", NEW_EXTERNAL)
    src = replace_method(src, "\tpublic static byte[] getBytes(Program program, AddressSetView addressSet)", NEW_GET_BYTES)
    old = 'throw new IllegalArgumentException("buffer does not contain relocation");'
    assert src.count(old) == 1
    src = src.replace(old, 'throw new IllegalArgumentException("buffer does not contain relocation at " + address '
                           '+ " width " + width);')
    src = add_imports(src, "import java.util.Map;\n", ["java.util.ArrayList", "java.util.HashSet", "java.util.List",
                                                       "java.util.TreeMap"])
    src = add_imports(src, "import ghidra.program.model.address.Address;\n", ["ghidra.program.model.address.AddressIterator"])
    src = add_imports(src, "import ghidra.program.model.symbol.SymbolTable;\n",
                      ["ghidra.program.model.symbol.ReferenceManager", "ghidra.program.model.symbol.Symbol",
                       "ghidra.program.model.symbol.SymbolIterator"])
    assert "getAllSymbols(true)" not in src
    return src


def patch_relocation_table(src: str) -> str:
    src = replace_method(src, "\tpublic Iterator<Relocation> getRelocations(AddressSetView iteratorAddressSet) {",
                         NEW_GET_RELOCATIONS)
    src = add_imports(src, "import java.util.Iterator;\n", ["java.util.ArrayList"])
    src = add_imports(src, "import ghidra.program.model.address.Address;\n", ["ghidra.program.model.address.AddressRange"])
    return src


def patch_x64_builder(src: str) -> str:
    # the dispatch: a third kind before the unknown-relocation fallthrough
    src = replace_once(src, '''			else {
				logUnknownRelocation(relTable.getSection(), relocation, log);
			}
		}
	}
''', '''			else if (relocation instanceof RelocationRelativeSymbol) {
				process(relTable, bytes, addressSet, (RelocationRelativeSymbol) relocation, symbol,
					log);
			}
			else {
				logUnknownRelocation(relTable.getSection(), relocation, log);
			}
		}
	}
''')
    src = replace_once(src, "\tprivate static CoffRelocationType relativePcType(int trailingBytes) {",
                       NEW_X64_RELSYM + "\tprivate static CoffRelocationType relativePcType(int trailingBytes) {")
    src = add_imports(src, "import ghidra.program.model.relocobj.RelocationRelativePC;\n",
                      ["ghidra.program.model.relocobj.RelocationRelativeSymbol",
                       "ghidra.app.analyzers.relocations.ImageBaseRelativeDataRelocationSynthesizer"])
    return src


def patch_absolute_data_synth(src: str) -> str:
    return replace_once(src, '''		if (!pointer.isInitializedMemory()) {
			return true;
		}
''', '''		if (!pointer.isInitializedMemory()) {
			return true;
		}
		if (ImageBaseRelativeDataRelocationSynthesizer.isImageBaseRelative(pointer)) {
			return true; // ATLAS 2026-10-30: an RVA field is the image-base-relative synthesizer's
		}
''')


def patch_x86_code_synth(src: str) -> str:
    src = replace_once(src, "\t@Override\n\tpublic List<FunctionInstructionSink> getFunctionInstructionSinks(",
                       NEW_X86_IBO_SINK + "\t@Override\n\tpublic List<FunctionInstructionSink> getFunctionInstructionSinks(")
    src = replace_once(src, '''		var absolute = new X86InstructionAbsoluteRelocationEmitter(analyzer, function,
			evaluationReporter, monitor, log);
		var relative = new X86InstructionRelativeRelocationEmitter(analyzer, function,
			evaluationReporter, monitor, log);

		return List.of(absolute, relative);
''', NEW_X86_SINKS)
    src = add_imports(src, "import ghidra.app.analyzers.relocations.emitters.RelativeNextInstructionRelocationEmitter;\n",
                      ["ghidra.app.analyzers.relocations.emitters.SymbolRelativeInstructionRelocationEmitter",
                       "ghidra.app.analyzers.relocations.utils.RelocationTarget",
                       "ghidra.program.model.address.Address",
                       "ghidra.program.model.symbol.Reference",
                       "ghidra.program.model.symbol.Symbol"])
    return src


def patch_exporter(src: str) -> str:
    """Part 3 (2026-10-30): a dynamic symbol's name gets its address appended unless it ends with it already. Ghidra
    names an offcut dynamic symbol (a reference into a datum) after the datum's label plus the field path, and the
    path repeats across the datum's offsets (`G._padding_` seven times in an FSystemSettings, `G._padding_+4`,
    `Set.Elements.AllocationFlags._padding_`), so the exporter's duplicate-symbol check failed 6 engine units once
    dynamic symbols were external (the folded unwind data). The exporter ties every relocation to the symbol at its
    exact target, so these names are the objects' symbols, defined and undefined through the same rule; Ghidra's
    default labels (`LAB_<va>`, `UNWIND_INFO_<va>`) end with the address and keep their names. func_match.py reads
    the address off the suffix."""
    unique = '''\t\t\t\t\t\tif (symbol.isDynamic() && !name.endsWith(address.toString())) {
\t\t\t\t\t\t\tname = name + "@" + address.toString();
\t\t\t\t\t\t}
'''
    defined = '''\t\t\t\t\t\tSymbol symbol = entry.getValue().getSymbol();
\t\t\t\t\t\tString name = entry.getValue().getName();
'''
    src = replace_once(src, defined, defined + unique)
    undefined = '''\t\t\t\t\tAddress address = entry.getKey();
\t\t\t\t\tString name = entry.getValue().getName();
'''
    src = replace_once(src, undefined, '''\t\t\t\t\tAddress address = entry.getKey();
\t\t\t\t\tSymbol symbol = entry.getValue().getSymbol();
\t\t\t\t\tString name = entry.getValue().getName();
''' + unique.replace("\t\t\t\t\t\t", "\t\t\t\t\t"))
    # Part 4 (2026-10-30, the first link): "inside a function" made 12 PDB publics static (functions whose entry
    # Ghidra left inside the previous function's body: IlmThread's Mutex, zlib's compressBound, ...), so the
    # objects that call them found no definition. A symbol the PDB named is external wherever it lies.
    src = replace_once(src, "\t\t\tPredicate<Symbol> predicate = new IsSymbolInsideFunction();\n",
                       "\t\t\tPredicate<Symbol> predicate = new IsSymbolInsideFunction()\n"
                       "\t\t\t\t\t.and(s -> s.getSource() != ghidra.program.model.symbol.SourceType.IMPORTED);\n")
    # Part 5 (2026-10-30, the first successful link): the ranges padded to 16 bytes (ProgramUtil.paddingOf), the
    # uninitialized sections sized the same way, the program told to ProgramUtil for the block names
    src = replace_once(src, "\t\tthis.fileSet = fileSet;\n", "\t\tthis.fileSet = fileSet;\n\t\tProgramUtil.paddingProgram = program;\n")
    src = replace_once(src, "\t\t\t\tlong virtualSize = sectionSet.getNumAddresses();\n",
                       "\t\t\t\tlong virtualSize = ProgramUtil.getPaddedSize(sectionSet);\n")
    return src


PATCHES = {PROGRAM_UTIL: patch_program_util, RELOC_TABLE: patch_relocation_table, X64_BUILDER: patch_x64_builder,
           ABS_DATA_SYNTH: patch_absolute_data_synth, X86_CODE_SYNTH: patch_x86_code_synth, EXPORTER: patch_exporter}
NEW_FILES = {IBO_DATA_SYNTH: IBO_DATA_SYNTH_SRC}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--restore", action="store_true", help="put the original jar back")
    a = ap.parse_args()
    orig = JAR.with_suffix(".jar.orig")
    if a.restore:
        if orig.exists():
            shutil.copy2(orig, JAR)
            print(f"restored {JAR} from {orig}")
        return
    srcdir, classes = WORK / "src", WORK / "classes"
    if classes.exists():
        shutil.rmtree(classes)
    classes.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(SRC) as z:
        for rel, fn in PATCHES.items():
            src = z.read("src/main/java/" + rel).decode("utf-8").replace("\r\n", "\n")
            out = srcdir / rel
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(fn(src), encoding="utf-8")
    for rel, src in NEW_FILES.items():
        out = srcdir / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(src, encoding="utf-8")
    # the original jar on the classpath (the unpatched classes resolve the rest); compile against the original
    if not orig.exists():
        shutil.copy2(JAR, orig)
    jars = sorted(str(p) for p in GHIDRA.glob("Ghidra/*/*/lib/*.jar")) + [str(orig)]
    jars += sorted(str(p) for p in (EXT / "lib").glob("bft-*.jar"))  # the COFF builder uses the bft types
    argfile = WORK / "javac.args"
    files = [str(srcdir / rel) for rel in [*PATCHES, *NEW_FILES]]
    argfile.write_text("-cp \"" + ";".join(jars).replace("\\", "/") + "\"\n-d \"" + str(classes).replace("\\", "/") +
                       "\"\n" + "\n".join(f"\"{f}\"".replace("\\", "/") for f in files) + "\n", encoding="utf-8")
    r = subprocess.run([str(JDK / "javac.exe"), "-nowarn", "-encoding", "utf-8", f"@{argfile}"], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        sys.exit("javac failed:\n" + (r.stdout + r.stderr)[-3000:])
    shutil.copy2(orig, JAR)  # start from the original, then add the patched classes (and their inner classes)
    members = sorted(str(p.relative_to(classes)).replace("\\", "/") for p in classes.rglob("*.class"))
    r = subprocess.run([str(JDK / "jar.exe"), "uf", str(JAR), "-C", str(classes), "."], capture_output=True,
                       text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        sys.exit("jar update failed:\n" + (r.stdout + r.stderr)[-2000:])
    print(f"patched {JAR}: {', '.join(members)}; original at {orig}; {len(jars)} jars on the classpath")


if __name__ == "__main__":
    main()
