/* ###
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

package dragonfang.matchers;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import dragonfang.features.maps.FeatureMap;
import dragonfang.features.vectors.FeatureVector;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class UniqueFeatureMatcher extends AbstractFeatureMatcher
{

    public UniqueFeatureMatcher(FeatureMap srcFeatureMap, FeatureMap dstFeatureMap)
    {
        super(srcFeatureMap, dstFeatureMap);
    }

    @Override
    public Set<Match> doMatch(Set<Function> unmatchedSrcFuncSet,
                              Set<Function> unmatchedDstFuncSet, TaskMonitor monitor)
        throws CancelledException
    {

        Set<Match> matches = new HashSet<Match>();

        HashMap<FeatureVector, List<Function>> srcMatchMap =
            deriveMatchMap(unmatchedSrcFuncSet, srcFeatureMap, monitor);
        HashMap<FeatureVector, List<Function>> dstMatchMap =
            deriveMatchMap(unmatchedDstFuncSet, dstFeatureMap, monitor);

        for (Function unmatchedSrcFunction : unmatchedSrcFuncSet) {
            FeatureVector featureVector =
                srcFeatureMap.getFeature(unmatchedSrcFunction, monitor);
            List<Function> srcFuncList = srcMatchMap.get(featureVector);

            if (srcFuncList.size() == 1) {
                List<Function> dstFuncList = dstMatchMap.get(featureVector);

                if (dstFuncList != null && dstFuncList.size() == 1) {
                    double similarity = 1.0;
                    double confidence = 1.0;
                    Match match =
                        new Match(unmatchedSrcFunction, dstFuncList.get(0), similarity,
                                  confidence, "Unique Feature Matcher");
                    matches.add(match);
                }
            }
        }

        return matches;
    }
}
