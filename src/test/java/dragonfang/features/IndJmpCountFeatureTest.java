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
import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counter.maps.LazyInstrCountMap;
import dragonfang.counters.InstrCounter;
import dragonfang.counters.PCodeInstrCounter;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class IndJmpCountFeatureTest extends AbstractDragonFangTest {

    @Test
    public void testIndJmpCountFeature() throws CancelledException {

        Function simpleFunction = getSimpleFunction(builder);

        TaskMonitor monitor = new ConsoleTaskMonitor();

        InstrCounter counter       = new PCodeInstrCounter();
        InstrCountMap countMap     = new LazyInstrCountMap(counter);
        IndJmpCountFeature feature = new IndJmpCountFeature(countMap);

        double featureVal = feature.calculateFeatureValue(simpleFunction, monitor);
        // Function only includes calls in terms of instructions that change control
        // flow.
        assertEquals("Call count should be 0.", 0, featureVal, 0.1);
    }
}
