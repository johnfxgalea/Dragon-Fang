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

package dragonfang.counter.maps;

import java.util.HashMap;
import java.util.Map;

import dragonfang.counters.InstrCounter;
import dragonfang.counters.InstrCounts;
import dragonfang.entities.Entity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LazyInstrCountMap implements InstrCountMap
{

    private Map<Entity, InstrCounts> instrCountMap;
    private InstrCounter counter;

    public LazyInstrCountMap(InstrCounter counter)
    {
        instrCountMap = new HashMap<Entity, InstrCounts>();
        this.counter = counter;
    }

    @Override
    public InstrCounts getInstructionCounts(Entity entity, TaskMonitor monitor)
        throws CancelledException
    {

        if (!instrCountMap.containsKey(entity)) {
            InstrCounts counts = counter.count(entity);
            instrCountMap.put(entity, counts);
        }

        return instrCountMap.get(entity);
    }
}
