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

import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.function.IntPredicate;

public class StringRangeIterator
    implements Iterator<Range>
{
    private final CodePointIterator codePointIterator;
    private final IntPredicate isStringCodePoint;
    private final int alignment;
    private Range nextRange;
    private CodePointOffset lookahead;

    public StringRangeIterator(CodePointIterator codePointIterator, IntPredicate isStringCodePoint, int alignment) {
        this.codePointIterator = codePointIterator;
        this.isStringCodePoint = isStringCodePoint;
        this.alignment = alignment;
        readLookahead();
        getNext();
    }
    
    private boolean validLookahead() {
        return lookahead != null && isStringCodePoint.test(lookahead.codePoint);
    }

    private boolean aligned() {
        return lookahead != null && lookahead.codePoint % alignment == 0;
    }
    
    private void readLookahead() {
        if (codePointIterator.hasNext()) {
            lookahead = codePointIterator.next();
        } else {
            lookahead = null;
        }
    }
    
    private void skipInvalid() {
        while (lookahead != null && !(validLookahead() && aligned())) {
            readLookahead();
        }
    }

    private void getNext() {
        skipInvalid();
        if (lookahead == null) {
            nextRange = null;
        } else {
            CodePointOffset start = lookahead;
            CodePointOffset end;
            List<Integer> codepointList = new LinkedList<>();
            do {
                end = lookahead;
                codepointList.add(lookahead.codePoint);
                readLookahead();
            } while (lookahead != null && validLookahead() && end.abuts(lookahead));
            if (end.codePoint != 0 && lookahead != null && lookahead.codePoint == 0 && end.abuts(lookahead)) {
                end = lookahead;
                codepointList.add(lookahead.codePoint);
                readLookahead();
            }
            final int[] codepointArray = codepointList.stream()
                .mapToInt(Integer::intValue)
                .toArray();
            nextRange = new Range(start.offset, end.offset + 1, codepointArray);
        }
    }
    
    @Override
    public boolean hasNext() {
        return nextRange != null;
    }

    @Override
    public Range next() {
        if (nextRange == null) {
            throw new NoSuchElementException();
        }
        try {
            return nextRange;
        } finally {
            getNext();
        }
    }
    
}