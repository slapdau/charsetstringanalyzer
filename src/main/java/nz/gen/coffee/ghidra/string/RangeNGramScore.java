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

import java.util.function.Function;

import ghidra.app.plugin.core.string.NGramUtils;
import ghidra.app.plugin.core.string.StringAndScores;

public class RangeNGramScore<T> {
    private final Function<? super T, String> accessor;
    private final boolean isLowerCaseModel;
    
    public RangeNGramScore(Function<? super T, String> accessor) {
        this.accessor = accessor;
        this.isLowerCaseModel = NGramUtils.isLowerCaseModel();
    }
    
    public boolean isAboveThreshold(T range) {
        StringAndScores candiate = new StringAndScores(accessor.apply(range), isLowerCaseModel);
        if (candiate.getScoredStringLength() < NGramUtils.getMinimumStringLength()) {
            return false;
        }
        NGramUtils.scoreString(candiate);
        return candiate.isScoreAboveThreshold();
    }
}