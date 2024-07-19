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

import java.util.Arrays;

import ghidra.framework.options.*;

public class SearchCharsets implements CustomOption {
    
    private static final String STATE_NAME = "charsets";
    
    private String[] charsets;
    
    public SearchCharsets() {
        this(new String[0]);
    }

    public SearchCharsets(String[] charsets) {
        this.charsets = charsets;
    }

    @Override
    public void readState(GProperties properties) {
        charsets = properties.getStrings(STATE_NAME, charsets);
    }
    
    @Override
    public void writeState(GProperties properties) {
    	properties.putStrings(STATE_NAME, charsets);
    }

    public String[] getCharsets() {
        return charsets;
    }
    
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((charsets == null) ? 0 : charsets.hashCode());
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
        SearchCharsets other = (SearchCharsets) obj;
        if (charsets == null) {
            if (other.charsets != null)
                return false;
        } else if (!charsets.equals(other.charsets))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "SearchCharsets " + Arrays.toString(charsets);
    }
    

}
