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

import static org.junit.Assert.*;
import org.junit.Test;

import dragonfang.features.vectors.ArrayFeatureVector;
import dragonfang.features.vectors.FeatureVector;

public class FeatureSimilarityMetricTest
{

    @Test
    public void CosineSimilarityTest()
    {
        FeatureSimilarityMetric metric = new CosineSimilarityMetric();

        FeatureVector vector1 = new ArrayFeatureVector(10);
        vector1.setFeature(5, 0);
        vector1.setFeature(0, 1);
        vector1.setFeature(3, 2);
        vector1.setFeature(0, 3);
        vector1.setFeature(2, 4);
        vector1.setFeature(0, 5);
        vector1.setFeature(0, 6);
        vector1.setFeature(2, 7);
        vector1.setFeature(0, 8);
        vector1.setFeature(0, 9);

        FeatureVector vector2 = new ArrayFeatureVector(10);
        vector2.setFeature(3, 0);
        vector2.setFeature(0, 1);
        vector2.setFeature(2, 2);
        vector2.setFeature(0, 3);
        vector2.setFeature(1, 4);
        vector2.setFeature(1, 5);
        vector2.setFeature(0, 6);
        vector2.setFeature(1, 7);
        vector2.setFeature(0, 8);
        vector2.setFeature(1, 9);

        double similarity = metric.calculateSimilarity(vector1, vector2);
        assertEquals("Must have correct similarity score.", 0.94, similarity, 0.01);
    }

    @Test
    public void CosineSimilarityTest2()
    {
        FeatureSimilarityMetric metric = new CosineSimilarityMetric();

        FeatureVector vector1 = new ArrayFeatureVector(10);
        FeatureVector vector2 = new ArrayFeatureVector(10);

        double similarity = metric.calculateSimilarity(vector1, vector2);
        assertEquals("Must have correct similarity score.", 0.0, similarity, 0);
    }

    @Test
    public void CosineSimilarityTest3()
    {
        FeatureSimilarityMetric metric = new CosineSimilarityMetric();

        FeatureVector vector1 = new ArrayFeatureVector(10);
        FeatureVector vector2 = new ArrayFeatureVector(10);

        for (int i = 0; i < vector1.numFeatures(); i++) {
            vector1.setFeature(i, i);
            vector2.setFeature(i, i);
        }

        double similarity = metric.calculateSimilarity(vector1, vector2);
        assertEquals("Must have correct similarity score.", 1, similarity, 0.01);
    }
}
