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

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.features.BBCountFeature;
import dragonfang.features.EdgeCountFeature;
import dragonfang.features.Feature;
import dragonfang.features.vectors.FeatureVector;
import dragonfang.graphs.maps.ControlFlowGraphMap;
import dragonfang.graphs.maps.LazyControlFlowGraphMap;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class FeatureExtractorTest extends AbstractDragonFangTest {

    @Test
    public void testBBFeatureExtractor() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);

        List<Feature> featureList = new ArrayList<Feature>();

        ControlFlowGraphMap cfgMap = new LazyControlFlowGraphMap();
        BBCountFeature feature     = new BBCountFeature(cfgMap);
        featureList.add(feature);

        FeatureExtractor extractor  = new FeatureListVectorExtractor(featureList);
        FeatureVector featureVector = extractor.extract(simpleFunction, monitor);

        assertEquals("Number of Features should be 1.", 1, featureVector.numFeatures());
        assertEquals("BB count should be 1.", 1, featureVector.getFeature(0), 0.1);
    }

    @Test
    public void testFeatureExtractor() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);

        List<Feature> featureList = new ArrayList<Feature>();

        ControlFlowGraphMap cfgMap = new LazyControlFlowGraphMap();
        BBCountFeature feature     = new BBCountFeature(cfgMap);
        featureList.add(feature);

        EdgeCountFeature feature2 = new EdgeCountFeature(cfgMap);
        featureList.add(feature2);

        FeatureExtractor extractor  = new FeatureListVectorExtractor(featureList);
        FeatureVector featureVector = extractor.extract(simpleFunction, monitor);

        assertEquals("Number of Features should be 2.", 2, featureVector.numFeatures());
        assertEquals("BB count should be 1.", 1, featureVector.getFeature(0), 0.1);
        assertEquals("Edge count should be 0.", 0, featureVector.getFeature(1), 0.1);
    }
}
