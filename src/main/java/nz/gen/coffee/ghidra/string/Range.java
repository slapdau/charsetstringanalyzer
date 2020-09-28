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

public class Range {

    public final int start;
    public final int end;
    public final int[] codepoints;

    public Range(int start, int end, int[] codepoints) {
        this.start = start;
        this.end = end;
        this.codepoints = codepoints;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Integer.hashCode(end);
        result = prime * result + Integer.hashCode(start);
        return result;
    }
    
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Range other = (Range) obj;
        if (end != other.end)
            return false;
        if (start != other.start)
            return false;
        return true;
    }
    
    @Override
    public String toString() {
        return "Range [start=" + start + ", end=" + end + ", text=["+ text() + "]]";
    }

    public int length() {
        return isNullTerminated()
            ? codepoints.length - 1
            : codepoints.length;
    }
    
    public String text() {
        return new String(codepoints, 0, length());
    }
    
    public boolean isNullTerminated() {
        return codepoints[codepoints.length - 1] == 0;
    }
    
}
