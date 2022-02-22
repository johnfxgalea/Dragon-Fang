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

public class CosineSimilarityMetric extends FeatureSimilarityMetric
{

    static final String NAME = "Cosine Similarity Metric";

    public CosineSimilarityMetric()
    {
        super(NAME);
    }

    @Override
    public double calculateSimilarity(FeatureVector vectorA, FeatureVector vectorB)
    {

        if (vectorA.numFeatures() == 0 || vectorB.numFeatures() == 0
            || (vectorA.numFeatures() != vectorB.numFeatures()))
            throw new IllegalArgumentException(
                "Invalid feature vector size passed as param.");

        double dotProd = 0.0;
        double dA = 0.0;
        double dB = 0.0;
        for (int i = 0; i < vectorA.numFeatures(); i++) {

            double featureA = vectorA.getFeature(i);
            double featureB = vectorB.getFeature(i);

            if (featureA < 0 || featureB < 0)
                throw new IllegalArgumentException("Negative feature value encountered.");

            dotProd += featureA * featureB;
            dA += Math.pow(featureA, 2);
            dB += Math.pow(featureB, 2);
        }

        if (dA <= 0 || dB <= 0)
            return 0.0;
        return dotProd / (Math.sqrt(dA) * Math.sqrt(dB));
    }
}