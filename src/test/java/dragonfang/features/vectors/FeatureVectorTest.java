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

import static org.junit.Assert.*;
import org.junit.Test;

public class FeatureVectorTest {

    @Test
    public void testFeatureVectorSize() {

        FeatureVector vector = new ArrayFeatureVector(10);
        assertEquals("Size should be consistent.", 10, vector.numFeatures());
    }

    @Test
    public void testFeatureVectorInit() {

        FeatureVector vector = new ArrayFeatureVector(10);

        for (int i = 0; i < 10; i++) {
            assertEquals(
                "Feature value should be initialised to 0.", 0, vector.getFeature(i), 0);
        }
    }

    @Test
    public void testFeatureVectorSet() {

        FeatureVector vector = new ArrayFeatureVector(10);

        for (int i = 0; i < 10; i++) {
            vector.setFeature(i, i);
        }

        for (int i = 0; i < 10; i++) {
            assertEquals("Must be equal to set value.", i, vector.getFeature(i), 0);
        }
    }
}
