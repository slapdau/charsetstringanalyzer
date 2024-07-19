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
/*
 * This file is heavily based on ghidra.app.plugin.core.string.StringsAnalyzer
 * and related classes from Ghidra 9.1.2_PUBLIC.
 * Modifications to use java.nio.charset.Charset classes for string searching
 * by Craig McGeachie
 */
package nz.gen.coffee.ghidra.string;

import java.awt.event.KeyEvent;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Spliterator;
import java.util.Spliterators;
import java.util.function.IntPredicate;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.string.NGramUtils;
import ghidra.app.plugin.core.string.StringTableOptions;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeImpl;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharsetInfo;
import ghidra.program.model.data.CharsetSettingsDefinition;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.DumbMemBufferImpl;
import ghidra.program.model.mem.MemBuffer;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBufferImpl;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.xml.XmlElement;
import ghidra.xml.XmlPullParser;
import ghidra.xml.XmlPullParserFactory;

public class CharsetStringAnalyzer extends AbstractAnalyzer {

    private static final String DESCRIPTION = "Searches for program strings and creates them in the binary.";
	private static final String NAME = "Charset String Analyzer";

	private static final String MODELFILE_OPT_NAME = "Model File";
	private static final String MODELFILE_OPT_DESC =
		"Model file built using Ghidra's BuildStringModels class. Any model files for this analyzer " +
			"should be located in the Ghidra/Features/Base/data/stringngrams directory and " +
			"end in \".sng\".";

	private static final String FORCE_MODEL_RELOAD_OPT_NAME = "Force Model Reload";
	private static final String FORCE_MODEL_RELOAD_OPT_DESC =
		"When checked, forces reload of model files every time the analyzer is run. When unchecked, " +
			"model files will only be reloaded when Ghidra is restarted or when model file option " +
			"name is changed.";

	private static final String MIN_STRING_LEN_OPT_NAME = "Minimum String Length";
	private static final String MIN_STRING_LEN_OPT_DESC =
		"The smallest number of characters in a string to be considered a valid string. " +
			"(Smaller numbers will give more false positives). String length must be 4 " +
			"or greater.";

	private static final String REQUIRE_NULL_TERMINATION_OPT_NAME =
		"Require Null Termination for String";
	private static final String REQUIRE_NULL_TERMINATION_OPTION_DESC =
		"If set to true, requires all strings to end in null.";

	private static final String ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME =
		"Create Strings Containing References";
	private static final String ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DESC =
		"If checked, allows a string that contains, but does not start with, one or more references" +
			" to be created.";

	private static final String ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME =
		"Create Strings Containing Existing Strings";
	private static final String ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DESC =
		"If checked, allows a string to be created even if it contains existing strings (existing " +
			"strings will be cleared). The string will be created only if existing strings (a) " +
			"are wholly contained within the potential string, (b) do not share the same starting " +
			"address as the potential string, (c) share the same ending address as the potential " +
			"string, and (d) are the same datatype as the potential string.";

	private static final String START_ALIGN_OPT_NAME = "String Start Alignment";
	private static final String START_ALIGN_OPT_DESC =
		"Specifies an alignment requirement for the start of the string. An alignment of 1 " +
			"means the string can start at any address.  An alignment of 2 means the string " +
			"must start on an even address and so on.  Only allowed values are 1,2, and 4.";

	private static final String END_ALIGN_OPT_NAME = "String end alignment";
	private static final String END_ALIGN_OPT_DESC =
		"Specifies an alignment requirement for the end of the string. An alignment of 1 " +
			"means the string can end at any address. Alignments greater than 1 require that " +
			"(a) the 'require null termination' option be enabled, and (b) if the null-terminated " +
			"string does not end at an aligned boundary, that there exist enough trailing '0' " +
			"bytes following the string to allow alignment. If neither (a) nor (b) apply, end " +
			"alignment is not enforced.";

	private static final String SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME =
		"Search Only in Accessible Memory Blocks";
	private static final String SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DESC =
		"If checked, this " +
			"analyzer only searches in memory blocks that have at least one of the Read (R), Write " +
			"(W), or Execute (X) permissions set to true. Enabling this option ensures that strings " +
			"are not created in areas such as overlays or debug sections.";
	
	private static final String SEARCHABLE_CHARSETS_NAME =
	    "Searchable Charsets";
    private static final String SEARCHABLE_CHARSETS_DESC =
        "Specifies which the character set encodings to use when searching the program for strings. " +
        "Strings will be searched for in the selected character set encodings.";

	// Default Values	
	private static final String MODELFILE_DEFAULT = "StringModel.sng";
	private static final boolean FORCE_MODEL_RELOAD_DEFAULT = false;
	private static final boolean REQUIRE_NULL_TERMINATION_DEFAULT = true;
	private static final boolean ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT = true;
	private static final boolean ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT = true;
	private static final boolean SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT = true;

	public static enum Alignment {
		ALIGN_1(1), ALIGN_2(2), ALIGN_4(4);
		private int alignment;

		Alignment(int alignment) {
			this.alignment = alignment;
		}

		public int getAlignment() {
			return alignment;
		}
	}

	public static enum MinStringLen {
		LEN_4(4),
		LEN_5(5),
		LEN_6(6),
		LEN_7(7),
		LEN_8(8),
		LEN_9(9),
		LEN_10(10),
		LEN_11(11),
		LEN_12(12),
		LEN_13(13),
		LEN_14(14),
		LEN_15(15),
		LEN_16(16),
		LEN_17(17),
		LEN_18(18),
		LEN_19(19),
		LEN_20(20),
		LEN_21(21),
		LEN_22(22),
		LEN_23(23),
		LEN_24(24),
		LEN_25(25);

		private int minLength;

		MinStringLen(int minLength) {
			this.minLength = minLength;
		}

		public int getMinLength() {
			return minLength;
		}
	}

	private static final Alignment START_ALIGN_DEFAULT = Alignment.ALIGN_1;
	private static final int END_ALIGN_DEFAULT = 4;
	private static final MinStringLen MIN_STRING_LEN_OPT_DEFAULT = MinStringLen.LEN_5;
	
	private String modelName = MODELFILE_DEFAULT;
	private boolean forceModelReload = FORCE_MODEL_RELOAD_DEFAULT;
	private int minStringLength = MIN_STRING_LEN_OPT_DEFAULT.getMinLength();
	private boolean requireNullEnd = REQUIRE_NULL_TERMINATION_DEFAULT;
	private int startAlignment = START_ALIGN_DEFAULT.getAlignment();
	private int endAlignment = END_ALIGN_DEFAULT;
	private boolean allowStringCreationWithOffcutReferences =
		ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT;
	private boolean allowStringCreationWithExistringSubstring =
		ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT;
	private boolean searchOnlyAccessibleMemBlocks = SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT;

	private final Set<SearchableCharset> configuredCharsets = getConfiguredCharsets();
	
	private final String[] searchableCharsets = configuredCharsets.stream()
        .map(sc -> sc.name)
        .collect(Collectors.toList())
        .toArray(String[]::new);
	private final SearchCharsets searchedCharsetsDefault = new SearchCharsets(configuredCharsets.stream()
        .filter(sc -> sc.enabledByDefault)
        .map(sc -> sc.name)
        .collect(Collectors.toList())
        .toArray(String[]::new));
	private SearchCharsets searchedCharsets = searchedCharsetsDefault;

	private String trigramFile = "StringModel.sng";

	public CharsetStringAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after().after().after().after().after());
		setPrototype();
		setDefaultEnablement(false);
		setSupportsOneTimeAnalysis();
	}
	
	@Override
	public boolean canAnalyze(Program program) {
		// As long as it has memory blocks defined, we can analyze
		return program.getMinAddress() != null;
	}

	private Set<SearchableCharset> getConfiguredCharsets() {
	    try {
	        return loadConfiguredCharsets();
	    } catch (SAXException | IOException ex) {
	        var defaultCharsets = new String[] {
                "US-ASCII",
                "UTF-8",
                "UTF-16BE",
                "UTF-16LE",
                "UTF-32BE",
                "UTF-32LE",
	        };
	        return Arrays.asList(defaultCharsets).stream()
	            .map(name -> new SearchableCharset(name, false))
	            .collect(Collectors.toSet());
	    }
	}
	
    private Set<SearchableCharset> loadConfiguredCharsets() throws SAXException, IOException {
        Set<String> availableCharsets = Arrays.asList(CharsetInfo.getInstance().getCharsetNames()).stream()
            .collect(Collectors.toSet());
        Set<SearchableCharset> disabled = new HashSet<>();
        Set<SearchableCharset> enabled = new HashSet<>();
        for (var file : findAllConfigFiles()) {
            Msg.info(this, "Loading config " + file);
            XmlPullParser parser = createParser(file);
            try {
                XmlElement charsets = parser.start("charsets");
                XmlElement charset;
                while ((charset = parser.softStart("charset")) != null) {
                    SearchableCharset searchableCharset = toSearchableCharset(charset, parser.end(charset));
                    if (CharsetInfo.isBOMCharset(searchableCharset.name)) {
                        Msg.warn(this, "Discarding BOM Charset: " + searchableCharset.name);
                        continue;
                    }
                    if (!availableCharsets.contains(searchableCharset.name)) {
                        Msg.warn(this, "Discarding unrecognised Charset: " + searchableCharset.name);
                        continue;
                    }
                    if (searchableCharset.enabledByDefault) {
                        enabled.add(searchableCharset);
                    } else {
                        disabled.add(searchableCharset);
                    }
                }
                parser.end(charsets);
            } finally {
                parser.dispose();
            }
        }

        Set<SearchableCharset> all = new HashSet<>();
        // Ordering is important. Add enabled before disabled.
        all.addAll(enabled);
        all.addAll(disabled);
        return all;
    }

    private Collection<ResourceFile> findAllConfigFiles() {
        return Application.findModuleSubDirectories("data").stream()
            .map(data -> new ResourceFile(data, "SearchableCharsets.xml"))
            .filter(ResourceFile::exists)
            .collect(Collectors.toList());
    }
    
    private XmlPullParser createParser(ResourceFile file) throws SAXException, IOException {
        ErrorHandler errorHandler = new ErrorHandler() {
            
            @Override
            public void error(SAXParseException exception) throws SAXException {
                Msg.error(CharsetStringAnalyzer.this, "Error parsing " + file, exception);
            }
            
            @Override
            public void fatalError(SAXParseException exception) throws SAXException {
                Msg.error(CharsetStringAnalyzer.this, "Fatal error parsing " + file, exception);
            }
            
            @Override
            public void warning(SAXParseException exception) throws SAXException {
                Msg.warn(CharsetStringAnalyzer.this, "Warning parsing " + file, exception);
            }
            
        };

        return XmlPullParserFactory.create(file, errorHandler, false);
    }

    private static SearchableCharset toSearchableCharset(XmlElement start, XmlElement end) {
        final boolean enabledByDefault;
        if (!start.hasAttribute("enabledByDefault")) {
            enabledByDefault = false;
        } else {
            enabledByDefault = Boolean.valueOf(start.getAttribute("enabledByDefault"));
        }
        return new SearchableCharset(end.getText(), enabledByDefault);
    }
    
    @Override
	public void registerOptions(Options options, Program program) {
		options.registerOption(MODELFILE_OPT_NAME, MODELFILE_DEFAULT, null,	MODELFILE_OPT_DESC);
		options.registerOption(MIN_STRING_LEN_OPT_NAME, MIN_STRING_LEN_OPT_DEFAULT, null, MIN_STRING_LEN_OPT_DESC);
		options.registerOption(REQUIRE_NULL_TERMINATION_OPT_NAME, REQUIRE_NULL_TERMINATION_DEFAULT, null, REQUIRE_NULL_TERMINATION_OPTION_DESC);
		options.registerOption(START_ALIGN_OPT_NAME, START_ALIGN_DEFAULT, null, START_ALIGN_OPT_DESC);
		options.registerOption(END_ALIGN_OPT_NAME, END_ALIGN_DEFAULT, null, END_ALIGN_OPT_DESC);
		options.registerOption(FORCE_MODEL_RELOAD_OPT_NAME, FORCE_MODEL_RELOAD_DEFAULT, null, FORCE_MODEL_RELOAD_OPT_DESC);
		options.registerOption(ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME, ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT, null, ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DESC);
		options.registerOption(ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME, ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT, null, ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DESC);
		options.registerOption(SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME, SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT, null, SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DESC);
		options.registerOption(SEARCHABLE_CHARSETS_NAME, OptionType.CUSTOM_TYPE, searchedCharsetsDefault, null, SEARCHABLE_CHARSETS_DESC, () -> new SearchCharsetsEditor(searchableCharsets));
	}

	@Override
	public void optionsChanged(Options options, Program program) {
		modelName = options.getString(MODELFILE_OPT_NAME, MODELFILE_DEFAULT);
		setTrigramFileName(modelName);

		minStringLength = options.getEnum(MIN_STRING_LEN_OPT_NAME,
				MIN_STRING_LEN_OPT_DEFAULT).getMinLength();

		requireNullEnd = options.getBoolean(REQUIRE_NULL_TERMINATION_OPT_NAME,
				REQUIRE_NULL_TERMINATION_DEFAULT);

		startAlignment = options.getEnum(START_ALIGN_OPT_NAME,
				START_ALIGN_DEFAULT).getAlignment();

		setStringEndAlignment(
			options.getInt(END_ALIGN_OPT_NAME, END_ALIGN_DEFAULT));

		forceModelReload =
			options.getBoolean(FORCE_MODEL_RELOAD_OPT_NAME, FORCE_MODEL_RELOAD_DEFAULT);

		allowStringCreationWithOffcutReferences =
			options.getBoolean(ALLOW_STRING_CREATION_WITH_MIDDLE_REF_NAME,
				ALLOW_STRING_CREATION_WITH_MIDDLE_REF_DEFAULT);

		allowStringCreationWithExistringSubstring =
			options.getBoolean(ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_NAME,
				ALLOW_STRING_CREATION_WITH_EXISTING_SUBSTR_DEFAULT);

		searchOnlyAccessibleMemBlocks = options.getBoolean(SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_NAME,
			SEARCH_ONLY_ACCESSIBLE_MEM_BLOCKS_DEFAULT);
		
		searchedCharsets = (SearchCharsets) options.getCustomOption(SEARCHABLE_CHARSETS_NAME, searchedCharsetsDefault);
		
	}

	private void setTrigramFileName(String name) {
		trigramFile = (name.endsWith(".sng")) ? name : (name + ".sng");
	}

	private void setStringEndAlignment(int alignment) {
		endAlignment = (alignment <= 0) ? 1 : alignment;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException
	{
		AddressFactory factory = program.getAddressFactory();
		AddressSpace[] addressSpaces = factory.getAddressSpaces();

		AddressSetView initializedMemory = program.getMemory().getLoadedAndInitializedAddressSet();

		try {

			NGramUtils.startNewSession(trigramFile, forceModelReload);

			if (set == null) {
				set = new AddressSet(initializedMemory);
			}

			AddressSet searchSet = initializedMemory.intersect(set);

			if (searchOnlyAccessibleMemBlocks) {

				// Intersect current AddressSet with accessible memory blocks
				MemoryBlock[] blocks = program.getMemory().getBlocks();
				AddressSet memoryBlockAddresses = getMemoryBlockAddresses(blocks);
				searchSet = searchSet.intersect(memoryBlockAddresses);
			}

			for (AddressSpace space : addressSpaces) {

				monitor.checkCancelled();

				// Portion of current address space that intersects with initialized memory
				AddressSet intersecting =
					searchSet.intersectRange(space.getMinAddress(), space.getMaxAddress());

				findStrings(program, intersecting, searchedCharsets.getCharsets(), monitor);
			}
		}
		catch (IOException e) {
			String msg =
				"Error accessing string model file: " + trigramFile + ": " + e.getMessage();
			log.appendMsg(msg);
			log.setStatus(msg);
			return false;
		}
		catch (Exception e) {
			Msg.error(this, "Unexpected exception during string analysis", e);
			log.setStatus("Unexpected exception during string analysis (see console)");
			return false;
		}

		return true;
	}

	private AddressSet getMemoryBlockAddresses(final MemoryBlock[] blocks) {

		AddressSet addresses = new AddressSet();
		for (MemoryBlock memBlock : blocks) {
			if (memBlock.getFlags() > 0) {
				addresses = addresses.union(new AddressSet(memBlock.getStart(), memBlock.getEnd()));
			}
		}
		return addresses;
	}

    /**
     * Searches the given addressSet for strings. 
     * <p>
     * Note: The address set searched will be modified before searching in the following ways:
     * <ul>
     * <li> if the given set is null, it will be re-initialized to encompass all of program memory</li>
     * <li> the set will be further culled to only include loaded memory blocks, if specified</li>
     * </ul>
     * <p>
     * @param program the program being searched.
     * @param addressSet the address set to search over; if null, will initialized to all memory
     * @param charsetNames character sets to use when searching for strings.
     * @param monitor the user monitor
     * @return the updated address set used for the search
     */
	private void findStrings(Program program, AddressSetView addressSet, String[] charsetNames, TaskMonitor monitor) {
        if (addressSet == null) addressSet = program.getMemory();
        addressSet = updateAddressesToSearch(program, addressSet);
        
        monitor.initialize(addressSet.getNumAddresses() * charsetNames.length);
        for (var charsetName : charsetNames) {
            Charset charset = Charset.forName(charsetName);
            for (var range : addressSet.getAddressRanges()) {
                if (monitor.isCancelled()) {
                    return;
                }
        
                searchRange(program, alignStart(range), charset, monitor);
            }
        }
	}
	
    /**
     * Returns a new address set that is the intersection of the given set with the
     * desired memory block addresses (loaded or unloaded).
     * <p>
     * Note: This desired set of memory blocks is known by inspecting the 
     * {@link StringTableOptions#useLoadedBlocksOnly()} attribute set by the user. 
     * @param addressSet the address set to update
     * 
     * @return new the new address set
     */
    private static AddressSetView updateAddressesToSearch(final Program program, AddressSetView addressSet) {
        return addressSet.intersect(program.getMemory().getLoadedAndInitializedAddressSet());
    }

    private AddressRange alignStart(AddressRange range) {
        return new AddressRangeImpl(
            align(range.getMinAddress(), startAlignment),
            range.getMaxAddress()
        );
    }

    private static Address align(final Address address, final int alignment) {
        long startOffset = address.getOffset();
        int padding = (alignment - (int)(startOffset % alignment)) % alignment;
        return address.getNewAddress(startOffset + padding);
    }
    
    private static final int CODEPOINT_UNDEFINED = Character.codePointAt(new char[] {KeyEvent.CHAR_UNDEFINED}, 0);

    public static boolean isPrintable(final int codepoint) {
        final Character.UnicodeBlock block = Character.UnicodeBlock.of(codepoint);
        return !(
            Character.isISOControl(codepoint) ||
            codepoint == CODEPOINT_UNDEFINED ||
            block == null ||
            block == Character.UnicodeBlock.SPECIALS
        );
    }

    public static boolean isPrintableAscii(final int codepoint) {
        return 32 <= codepoint && codepoint <= 126;
    }


    private Stream<Range> findStringRanges(Charset charset, Iterator<byte[]> mem, IntPredicate inString) {
        var codePointIterator = new CodePointIterator(charset, mem);
        var rangeIterator = new StringRangeIterator(codePointIterator, inString, startAlignment);
        var rangeSpliterator = Spliterators.spliteratorUnknownSize(rangeIterator, Spliterator.DISTINCT | Spliterator.ORDERED);
        return StreamSupport.stream(() -> rangeSpliterator, Spliterator.DISTINCT | Spliterator.ORDERED, false);
    }

    private static CharBuffer toCharBuffer(CharsetDecoder decoder, Program program, AddressRange range) {
        MemBuffer membuf = new DumbMemBufferImpl(program.getMemory(), range.getMinAddress());
        byte[] bytes = new byte[(int)range.getLength()];
        int bytesRead = membuf.getBytes(bytes, 0);
        if (bytesRead != bytes.length) {
            return null;
        }
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        try {
            return decoder.decode(byteBuffer);
        } catch (CharacterCodingException e) {
            // Shouldn't happen.
            throw new Error(e);
        }
    }
    
    private void searchRange(Program program, AddressRange addressRange, Charset charset, TaskMonitor monitor) {
        MemBuffer memBuffer = new MemoryBufferImpl(program.getMemory(), addressRange.getMinAddress());
        MemBufferIterator memBufferIterator = new MemBufferIterator(memBuffer, addressRange.getLength(), monitor);
        findStringRanges(charset, memBufferIterator, CharsetStringAnalyzer::isPrintableAscii)
            .filter(range -> !(requireNullEnd && range.isNullTerminated()))
            .filter(range -> range.length() >= minStringLength)
            .filter(new RangeNGramScore<>(Range::text)::isAboveThreshold)
            .map(range -> toAddressRange(addressRange.getMinAddress(), range))
            .filter(range -> allowWithExistingSubstring(program, range, StringDataType.dataType))
            .filter(range -> allowWithOffcutReferences(program, range))
            .map(range -> alignNullEnd(program, range))
            .forEach(range -> { create(program, monitor, charset, range, StringDataType.dataType); });
    }
    
    private static AddressRange toAddressRange(Address base, Range range) {
        Address resultStart = base.getNewAddress(base.getOffset() + range.start);
        Address resultEnd = base.getNewAddress(base.getOffset() + range.end - 1);
        return new AddressRangeImpl(resultStart, resultEnd);
    }
    
    private boolean allowWithExistingSubstring(Program program, AddressRange stringRange, AbstractStringDataType datatype) {
        Address stringStart = stringRange.getMinAddress();
        Address stringEnd = stringRange.getMaxAddress();
        Listing listing = program.getListing();
        if (!DataUtilities.isUndefinedRange(program, stringStart, stringEnd)) {
            if (allowStringCreationWithExistringSubstring) {
                // Check for single string with a common end address which be consumed
                Data definedData = listing.getDefinedDataContaining(stringEnd);
                if (definedData == null || definedData.getAddress().compareTo(stringStart) <= 0 ||
                    !datatype.isEquivalent(definedData.getDataType()) ||
                    !DataUtilities.isUndefinedRange(program, stringStart,
                        definedData.getAddress().previous())) {
                    return false; // conflict data can not be consumed
                }
            }
            else {
                return false; // data conflict
            }
        }
        return true;
    }
    
    private boolean allowWithOffcutReferences(Program program, AddressRange stringRange) {
        if (allowStringCreationWithOffcutReferences) {
            return true;
        }
        Address endAddress = stringRange.getMaxAddress();
        Address currentAddress = stringRange.getMinAddress().next();
        while (currentAddress != null && currentAddress.compareTo(endAddress) <= 0) {
            if (program.getReferenceManager().hasReferencesTo(currentAddress)) {
                return false;
            }
            currentAddress = currentAddress.next();
        }
        return true;
    }
    
    private void create(Program program, TaskMonitor monitor, Charset charset, AddressRange stringRange, AbstractStringDataType datatype) {
        ClearDataMode clearDataMode = DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA;
        CharsetDecoder decoder = charset
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        try {
            Data string = DataUtilities.createData(program, stringRange.getMinAddress(), datatype, (int) stringRange.getLength(), false, clearDataMode);
            CharsetSettingsDefinition.CHARSET.setCharset(string, charset.name());
            Msg.trace(this, "Created string '" + toCharBuffer(decoder, program, stringRange) + "' at " + stringRange.getMinAddress());
            monitor.setMessage("Creating String at " + stringRange.getMinAddress());
        } catch (CodeUnitInsertionException e) {
            throw new AssertException("Unexpected exception", e);
        }
    }

	private AddressRange alignNullEnd(Program program, AddressRange range) {
	    if (!requireNullEnd) {
	        return range;
	    }
        Address endAddress = range.getMaxAddress();
        long nextOffset = endAddress.next().getOffset();
        int padding = (endAlignment - (int)(nextOffset % endAlignment)) % endAlignment;
        try {
            for (int count = 0; count != padding; ++count) {
                endAddress = endAddress.next();
                if (endAddress == null) return range;
                if (program.getMemory().getByte(endAddress) != 0) return range;
                CodeUnit cu = program.getListing().getCodeUnitContaining(endAddress);
                if (cu == null) return range;
                if (!(cu instanceof Data) || ((Data) cu).isDefined()) return range;
            }
        } catch (MemoryAccessException e) {
            return range;
        }
	    return new AddressRangeImpl(range.getMinAddress(), endAddress);
	}
	

}