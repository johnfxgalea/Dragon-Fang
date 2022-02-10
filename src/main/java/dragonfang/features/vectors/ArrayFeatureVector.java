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

package dragonfang.features.vectors;

import java.util.Arrays;

/**
 * Array-based feature vector.
 */
public class ArrayFeatureVector implements FeatureVector {

    // We maintain the feature vector as an array.
    private double[] featureVector;

    public ArrayFeatureVector(int size) {
        featureVector = new double[size];
    }

    @Override
    public void setFeature(double feature, int index) {

        // Ensure correct index.
        if (index < 0 || index >= featureVector.length)
            throw new IllegalArgumentException(
                "Invalid feature vector size passed as param.");

        // Simply set the value!
        featureVector[index] = feature;
    }

    @Override
    public boolean equals(Object obj) {

        if (!(obj instanceof ArrayFeatureVector))
            return false;

        if (featureVector.length != ((ArrayFeatureVector) obj).featureVector.length)
            return false;

        for (int i = 0; i < featureVector.length; i++)
            if (featureVector[i] != ((ArrayFeatureVector) obj).featureVector[i])
                return false;

        return true;
    }

    @Override
    public int hashCode() {

        // Convert to string then get hashcode.
        // TODO: Maybe hashing can be a bit more efficient but it will do for now.
        return Arrays.toString(featureVector).hashCode();
    }

    @Override
    public double getFeature(int index) {

        if (index < 0 || index >= featureVector.length)
            throw new IllegalArgumentException(
                "Invalid feature vector size passed as param.");

        // Simply return the feature value at the passed index.
        return featureVector[index];
    }

    @Override
    public int numFeatures() {

        return featureVector.length;
    }

    @Override
    public String toString() {
        return Arrays.toString(featureVector);
    }
}
