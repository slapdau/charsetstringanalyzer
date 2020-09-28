# Charset String Analyzer

This project is an add-on module for the Ghidra Software Reverse Engineering
Framework. It is intended as a replacement for built in string analyzer, and
offers all the same capabilities.

The Charset String Analyzer doesn't decode strings directly. It uses Java
character sets (implmentations of `java.nio.charset.Charset`) to do the
decoding. There are a wide range of built in Java character sets (including
single-byte and multi-byte versions of Unicode) and more can be added with a
well defined service provider extension mechanism.

The motivation for writing the plugin was to be able to analyze Apple II program
binaries, which often have strings encoded as ASCII, but with the high bit set.
That is, 'A' would be encoded as `0xC1` instead of `0x41`.

By default, strings can be searched for in:
 - US-ASCII
 - UTF-8
 - UTF-16BE
 - UTF-16LE
 - UTF-32BE
 - UTF-32LE

For additional information on how to use this modules extension capabilities to
search for strings in new character sets see `data/SearchableCharsets.xml`.
