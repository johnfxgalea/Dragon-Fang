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

import dragonfang.entities.Entity;
import dragonfang.features.maps.FeatureMap;
import dragonfang.features.metrics.FeatureSimilarityMetric;
import dragonfang.features.vectors.FeatureVector;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class SimilarityFeatureMatcher extends AbstractFeatureMatcher
{

    private FeatureSimilarityMetric similarityMetric;
    private double thresholdLimit;

    public SimilarityFeatureMatcher(FeatureMap srcFeatureMap, FeatureMap dstFeatureMap,
                                    FeatureSimilarityMetric similarityMetric,
                                    double thresholdLimit)
    {
        super(srcFeatureMap, dstFeatureMap);

        this.similarityMetric = similarityMetric;
        this.thresholdLimit = thresholdLimit;
    }

    @Override
    public Set<Match> doMatch(Set<Entity> unmatchedSrcEntitySet,
                              Set<Entity> unmatchedDstEntitySet, TaskMonitor monitor)
        throws CancelledException
    {

        Set<Match> matches = new HashSet<Match>();

        HashMap<FeatureVector, List<Entity>> srcMatchMap =
            deriveMatchMap(unmatchedSrcEntitySet, srcFeatureMap, monitor);
        HashMap<FeatureVector, List<Entity>> dstMatchMap =
            deriveMatchMap(unmatchedDstEntitySet, dstFeatureMap, monitor);

        for (Map.Entry<FeatureVector, List<Entity>> srcEntry : srcMatchMap.entrySet()) {
            FeatureVector srcFeatureVector = srcEntry.getKey();
            List<Entity> srcEntityList = srcEntry.getValue();

            if (srcEntityList.size() == 1) {
                double bestSimilarity = 0;
                List<Entity> bestDstEntityList = srcEntry.getValue();

                for (Map.Entry<FeatureVector, List<Entity>> dstEntry :
                     dstMatchMap.entrySet()) {
                    FeatureVector dstFeatureVector = dstEntry.getKey();
                    List<Entity> dstEntityList = dstEntry.getValue();

                    double similarity = similarityMetric.calculateSimilarity(
                        srcFeatureVector, dstFeatureVector);
                    if (similarity > bestSimilarity) {
                        bestDstEntityList = dstEntityList;
                        bestSimilarity = similarity;
                    }
                }

                if (bestDstEntityList != null && bestDstEntityList.size() == 1) {
                    if (thresholdLimit <= bestSimilarity) {
                        double confidence = 1.0;
                        Match match = new Match(srcEntityList.get(0),
                                                bestDstEntityList.get(0), bestSimilarity,
                                                confidence, "Similarity Feature Matcher");
                        matches.add(match);
                    }
                }
            }
        }

        return matches;
    }
}
