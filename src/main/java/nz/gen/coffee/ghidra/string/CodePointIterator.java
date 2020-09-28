/*
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
package nz.gen.coffee.ghidra.string;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

public class CodePointIterator
    implements Iterator<CodePointOffset>
{
    private final Charset charset;
    private final CharsetDecoder decoder;
    private final Iterator<byte[]> input;

    private int prevBufferLen = 0;
    private ByteBuffer inputBuffer;
    private boolean hasNext;
    private int next;
    private int nextOffset;
    private int inputOffset = 0;
    private CharBuffer readBuffer;
    
    public CodePointIterator(Charset charset, byte[] input) {
        this(charset, Arrays.asList(input).iterator());
    }
    
    public CodePointIterator(Charset charset, Iterator<byte[]> input) {
        this.charset = charset;
        this.decoder = charset
            .newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT);
        this.input = input;
        readBuffer = CharBuffer.allocate(128);
        readBuffer.position(readBuffer.limit()); // Mark the buffer as empty to force an initial load in getNext()
        if (input.hasNext()) {
            inputBuffer = ByteBuffer.wrap(input.next());
            getNext();
        } else {
            hasNext = false;
        }
    }

    private void loadInputBuffer() {
        prevBufferLen += inputBuffer.position();
        byte[] nextInputBytes = input.next();
        ByteBuffer nextInputBuffer = ByteBuffer.allocate(inputBuffer.remaining() + nextInputBytes.length);
        nextInputBuffer.put(inputBuffer);
        nextInputBuffer.put(nextInputBytes);
        nextInputBuffer.rewind();
        inputBuffer = nextInputBuffer;
    }

    private void loadReadBuffer() {
        readBuffer.clear();
        CoderResult coderResult;
        int nextInputOffset = -1;
        for (;;) {
            nextInputOffset = prevBufferLen + inputBuffer.position();
            coderResult = decoder.decode(inputBuffer, readBuffer, !input.hasNext());
            if (coderResult.isUnderflow() && input.hasNext()) {
                loadInputBuffer();
            }
            if (readBuffer.position() != 0 || !inputBuffer.hasRemaining()) break;
            if (coderResult.isError()) {
                if (coderResult.length() > inputBuffer.remaining() && input.hasNext()) {
                    loadInputBuffer();
                }
                inputBuffer.position(inputBuffer.position()+coderResult.length());
            }
        }
        inputOffset = nextInputOffset;
        readBuffer.flip();
    }

    private void loadReadBufferIfEmpty() {
        if (!readBuffer.hasRemaining()) {
            loadReadBuffer();
        }
    }
    
    private int countBytes(char[] chars) {
        try {
            return CharsetUtil.countBytes(charset, chars);
        } catch (CharacterCodingException e) {
            // Shouldn't happen. The characters were successfully decoded.
            // Should be no issues re-encoding.
            throw new Error(e);
        }
    }

    private int countBytes(int codepoint) {
        return countBytes(Character.toChars(codepoint));
    }

    private void getNext() {
        hasNext = readBuffer.hasRemaining() || inputBuffer.hasRemaining();
        if (!hasNext) {
            return;
        }
        loadReadBufferIfEmpty();
        if (!readBuffer.hasRemaining()) {
            hasNext = false;
            return;
        }
        char c1 = readBuffer.get();
        if (Character.isHighSurrogate(c1)) {
            loadReadBufferIfEmpty();
            if (readBuffer.length() != 0 && Character.isLowSurrogate(readBuffer.charAt(0))) {
                char c2 = readBuffer.get();
                next = Character.toCodePoint(c1, c2);
            }
        }
        next = c1;
        nextOffset = inputOffset;
        inputOffset += countBytes(next);
    }

    @Override
    public boolean hasNext() {
        return hasNext;
    }

    @Override
    public CodePointOffset next() {
        if (!hasNext) {
            throw new NoSuchElementException();
        }
        try {
            return new CodePointOffset(nextOffset, next, countBytes(next));
        } finally {
            getNext();
        }
    }
}