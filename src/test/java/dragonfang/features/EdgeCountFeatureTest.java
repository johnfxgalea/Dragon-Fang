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
import dragonfang.features.functions.EdgeCountFeature;
import dragonfang.graphs.maps.ControlFlowGraphMap;
import dragonfang.graphs.maps.LazyControlFlowGraphMap;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class EdgeCountFeatureTest extends AbstractDragonFangTest
{

    @Test
    public void testEdgeCountFeature() throws CancelledException
    {

        Function simpleFunction = getSimpleFunction(builder);

        TaskMonitor monitor = new ConsoleTaskMonitor();

        ControlFlowGraphMap cfgMap = new LazyControlFlowGraphMap();

        EdgeCountFeature feature = new EdgeCountFeature(cfgMap);
        double featureVal = feature.calculateFeatureValue(simpleFunction, monitor);
        // Function only includes calls in terms of instructions that change control
        // flow.
        assertEquals("Edge count should be 0.", 0, featureVal, 0.1);
    }
}
