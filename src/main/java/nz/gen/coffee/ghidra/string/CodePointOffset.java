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

public class CodePointOffset {
    public final int offset;
    public final int codePoint;
    public final int size;
    
    public CodePointOffset(int offset, int codePoint, int size) {
        this.codePoint = codePoint;
        this.offset = offset;
        this.size = size;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + Integer.hashCode(offset);
        result = prime * result + codePoint;
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
        CodePointOffset other = (CodePointOffset) obj;
        if (offset != other.offset)
            return false;
        if (codePoint != other.codePoint)
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "CodePointOffset [offset=" + offset + ", char=" + new String(new int[] {codePoint}, 0, 1) + "]";
    }
    
    public boolean abuts(CodePointOffset next) {
        return this.offset + this.size == next.offset;        
    }
}