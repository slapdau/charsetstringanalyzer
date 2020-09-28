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

import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.util.Arrays;
import java.util.stream.Collectors;

public interface CharsetUtil {

    public static int countBytes(Charset charset, char[] chars) throws CharacterCodingException {
        return countBytes(charset, CharBuffer.wrap(chars));
    }

    public static int countBytes(Charset charset, char[] chars, int start, int end) throws CharacterCodingException {
        return countBytes(charset, CharBuffer.wrap(chars, start, end));
    }

    public static int countBytes(Charset charset, CharBuffer input) throws CharacterCodingException {
    	CharsetEncoder encoder = charset
    		.newEncoder()
    		.onMalformedInput(CodingErrorAction.REPORT)
    		.onUnmappableCharacter(CodingErrorAction.REPORT);
    	return encoder.encode(input).remaining();
    }

    public static int countBytes(Charset charset, int[] codepoints) throws CharacterCodingException {
    	return countBytes(charset, toCharBuffer(codepoints));
    }

    public static int countBytes(Charset charset, int[] codepoints, int start, int end) throws CharacterCodingException {
    	return countBytes(charset, toCharBuffer(codepoints, start, end));
    }

    public static CharBuffer toCharBuffer(int[] codepoints) {
    	return toCharBuffer(codepoints, 0, codepoints.length);
    }

    public static CharBuffer toCharBuffer(int[] codepoints, int start, int end) {
    	CharBuffer input = Arrays.stream(codepoints, start, end)
    		.mapToObj(Character::toChars)
    		.map(CharBuffer::wrap)
    		.collect(Collectors.collectingAndThen(Collectors.joining(), CharBuffer::wrap));
    	return input;
    }

}
