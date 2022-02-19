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

package dragonfang.features.metrics;

import dragonfang.features.vectors.FeatureVector;

public abstract class FeatureSimilarityMetric
{

    private final String name;

    public FeatureSimilarityMetric(String name)
    {
        this.name = name;
    }

    /**
     * Calculates similarity between two feature vectors.
     *
     * @param vector1 The first feature vector to compare.
     * @param vector2 The second feature vector to compare.
     * @return The similarity score.
     */
    public abstract double calculateSimilarity(FeatureVector vector1,
                                               FeatureVector vector2);

    /**
     * Returns the name of the similarity metric.
     *
     * @return The name.
     */
    public String getName()
    {
        return name;
    }

    @Override
    public String toString()
    {
        return name;
    }
}
