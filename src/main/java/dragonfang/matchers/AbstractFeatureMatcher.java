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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import dragonfang.entities.Entity;
import dragonfang.features.maps.FeatureMap;
import dragonfang.features.vectors.FeatureVector;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public abstract class AbstractFeatureMatcher implements Matcher
{

    protected FeatureMap srcFeatureMap;
    protected FeatureMap dstFeatureMap;

    public AbstractFeatureMatcher(FeatureMap srcFeatureMap, FeatureMap dstFeatureMap)
    {

        this.srcFeatureMap = srcFeatureMap;
        this.dstFeatureMap = dstFeatureMap;
    }

    protected HashMap<FeatureVector, List<Entity>>
    deriveMatchMap(Set<Entity> unmatchedFuncSet, FeatureMap featureMap,
                   TaskMonitor monitor) throws CancelledException
    {

        HashMap<FeatureVector, List<Entity>> matchMap =
            new HashMap<FeatureVector, List<Entity>>();

        for (Entity unmatchedEntity : unmatchedFuncSet) {
            FeatureVector featureVector = featureMap.getFeature(unmatchedEntity, monitor);

            List<Entity> entitySet = matchMap.get(featureVector);
            if (entitySet == null) {
                entitySet = new ArrayList<Entity>();
                matchMap.put(featureVector, entitySet);
            }
            entitySet.add(unmatchedEntity);
        }

        return matchMap;
    }
}
