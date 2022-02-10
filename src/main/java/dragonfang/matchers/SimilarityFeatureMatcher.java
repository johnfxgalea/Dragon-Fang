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
import java.util.Map;
import java.util.Set;

import dragonfang.features.maps.FeatureMap;
import dragonfang.features.metrics.FeatureSimilarityMetric;
import dragonfang.features.vectors.FeatureVector;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SimilarityFeatureMatcher extends AbstractFeatureMatcher {

    private FeatureSimilarityMetric similarityMetric;

    public SimilarityFeatureMatcher(FeatureMap srcFeatureMap,
                                    FeatureMap dstFeatureMap,
                                    FeatureSimilarityMetric similarityMetric) {
        super(srcFeatureMap, dstFeatureMap);

        this.similarityMetric = similarityMetric;
    }

    @Override
    public Set<Match> doMatch(Set<Function> unmatchedSrcFuncSet,
                              Set<Function> unmatchedDstFuncSet,
                              TaskMonitor monitor) throws CancelledException {

        Set<Match> matches = new HashSet<Match>();

        HashMap<FeatureVector, List<Function>> srcMatchMap =
            deriveMatchMap(unmatchedSrcFuncSet, srcFeatureMap, monitor);
        HashMap<FeatureVector, List<Function>> dstMatchMap =
            deriveMatchMap(unmatchedDstFuncSet, dstFeatureMap, monitor);

        for (Map.Entry<FeatureVector, List<Function>> srcEntry : srcMatchMap.entrySet()) {
            FeatureVector srcFeatureVector = srcEntry.getKey();
            List<Function> srcFuncList     = srcEntry.getValue();

            if (srcFuncList.size() == 1) {
                double bestSimilarity          = 0;
                List<Function> bestDstFuncList = srcEntry.getValue();

                for (Map.Entry<FeatureVector, List<Function>> dstEntry :
                     dstMatchMap.entrySet()) {
                    FeatureVector dstFeatureVector = dstEntry.getKey();
                    List<Function> dstFuncList     = dstEntry.getValue();

                    double similarity = similarityMetric.calculateSimilarity(
                        srcFeatureVector, dstFeatureVector);
                    if (similarity > bestSimilarity)
                        bestDstFuncList = dstFuncList;
                }

                if (bestDstFuncList != null && bestDstFuncList.size() == 1) {
                    double confidence = 1.0;
                    Match match       = new Match(srcFuncList.get(0),
                                            bestDstFuncList.get(0),
                                            bestSimilarity,
                                            confidence,
                                            "Similarity Feature Matcher");
                    matches.add(match);
                }
            }
        }

        return matches;
    }
}
