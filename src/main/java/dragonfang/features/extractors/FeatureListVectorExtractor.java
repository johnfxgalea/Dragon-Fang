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

package dragonfang.features.extractors;

import java.util.List;
import dragonfang.features.Feature;
import dragonfang.features.vectors.ArrayFeatureVector;
import dragonfang.features.vectors.FeatureVector;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Construct feature vector from a list of features.
 */
public class FeatureListVectorExtractor implements FeatureExtractor
{

    private List<Feature> featureList;

    public FeatureListVectorExtractor(List<Feature> featureList)
    {

        this.featureList = featureList;
    }

    public FeatureVector extract(Function function, TaskMonitor monitor)
        throws CancelledException
    {

        // Iterate through the feature list, calculating each feature value and storing
        // in the vector.
        FeatureVector featureVector = new ArrayFeatureVector(featureList.size());

        for (int i = 0; i < featureList.size(); i++) {
            Feature feature = featureList.get(i);
            // Get value and set.
            double featureValue = feature.calculateFeatureValue(function, monitor);
            featureVector.setFeature(featureValue, i);
        }

        return featureVector;
    }
}
