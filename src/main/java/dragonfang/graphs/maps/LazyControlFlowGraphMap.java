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

package dragonfang.graphs.maps;

import java.util.HashMap;
import java.util.Map;

import dragonfang.graphs.ControlFlowGraph;
import dragonfang.graphs.builders.ControlFlowGraphBuilder;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class LazyControlFlowGraphMap implements ControlFlowGraphMap {

    private Map<Function, ControlFlowGraph> cfgMap;

    public LazyControlFlowGraphMap() {
        this.cfgMap = new HashMap<Function, ControlFlowGraph>();
    }

    @Override
    public ControlFlowGraph getControlFlowGraph(Function function, TaskMonitor monitor)
        throws CancelledException {

        if (!cfgMap.containsKey(function)) {
            ControlFlowGraphBuilder builder = new ControlFlowGraphBuilder(function);
            ControlFlowGraph cfg = (ControlFlowGraph) builder.buildGraph(monitor);
            cfgMap.put(function, cfg);
        }

        return cfgMap.get(function);
    }
}
