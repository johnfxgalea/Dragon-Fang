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

package dragonfang.counters.maps;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counter.maps.LazyInstrCountMap;
import dragonfang.counters.InstrCounts;
import dragonfang.counters.PCodeInstrCounter;
import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class InstrCountMapTest extends AbstractDragonFangTest
{

    @Test
    public void testPCodeInstrCounterXOR() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);
        Entity entity = new FunctionEntity(simpleFunction);

        PCodeInstrCounter instrCounter = new PCodeInstrCounter();
        InstrCountMap instrCountMap = new LazyInstrCountMap(instrCounter);

        InstrCounts counts = instrCountMap.getInstructionCounts(entity, monitor);
        assertEquals("Count should be 0.", 0, counts.getCount(PcodeOp.BOOL_XOR));
    }

    @Test
    public void testPCodeInstrCounterCALLIND() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction = getSimpleFunction(builder);
        Entity entity = new FunctionEntity(simpleFunction);

        PCodeInstrCounter instrCounter = new PCodeInstrCounter();
        InstrCountMap instrCountMap = new LazyInstrCountMap(instrCounter);

        InstrCounts counts = instrCountMap.getInstructionCounts(entity, monitor);
        assertEquals("Count should be 2.", 2, counts.getCount(PcodeOp.CALLIND));
    }
}
