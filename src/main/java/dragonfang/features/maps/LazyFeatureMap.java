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

package dragonfang.features.maps;

import java.util.HashMap;
import java.util.Map;

import dragonfang.entities.Entity;
import dragonfang.features.extractors.FeatureExtractor;
import dragonfang.features.vectors.FeatureVector;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LazyFeatureMap implements FeatureMap
{

    private FeatureExtractor featureExtractor;
    private Map<Entity, FeatureVector> featureMap;

    public LazyFeatureMap(FeatureExtractor featureExtractor)
    {

        this.featureExtractor = featureExtractor;
        this.featureMap = new HashMap<Entity, FeatureVector>();
    }

    @Override
    public FeatureVector getFeature(Entity entity, TaskMonitor monitor)
        throws CancelledException
    {

        if (!featureMap.containsKey(entity)) {
            FeatureVector featureVector = featureExtractor.extract(entity, monitor);
            featureMap.put(entity, featureVector);
        }

        return featureMap.get(entity);
    }
}
