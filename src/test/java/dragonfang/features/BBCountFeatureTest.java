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

package dragonfang.features;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.graphs.maps.ControlFlowGraphMap;
import dragonfang.graphs.maps.LazyControlFlowGraphMap;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class BBCountFeatureTest extends AbstractDragonFangTest {

    @Test
    public void testBBCountFeature() throws CancelledException {

        Function simpleFunction = getSimpleFunction(builder);

        TaskMonitor monitor = new ConsoleTaskMonitor();

        ControlFlowGraphMap cfgMap = new LazyControlFlowGraphMap();

        BBCountFeature feature = new BBCountFeature(cfgMap);
        double featureVal      = feature.calculateFeatureValue(simpleFunction, monitor);
        // Function only includes calls in terms of instructions that change control flow.
        assertEquals("BB count should be 1.", 1, featureVal, 0.1);
    }
}
