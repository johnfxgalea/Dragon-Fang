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

package dragonfang.graphs.builders;

import java.util.Map;
import java.util.Set;

import dragonfang.graphs.CallGraph;
import dragonfang.graphs.ExtendedDirectGraph;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.Edge;
import ghidra.util.graph.Vertex;
import ghidra.util.task.TaskMonitor;

public class CallGraphBuilder implements GraphBuilder {

    protected Program prog;

    public CallGraphBuilder(Program prog) {
        this.prog = prog;
    }

    @Override
    public ExtendedDirectGraph buildGraph(TaskMonitor monitor) throws CancelledException {

        FunctionManager funcManager = prog.getFunctionManager();
        CallGraph callGraph         = new CallGraph();
        FunctionIterator funcIt     = funcManager.getFunctions(true);

        // Step 1: Iterate over functions to set up vertices.
        while (funcIt.hasNext()) {
            Function function = funcIt.next();
            Vertex vertex     = new Vertex(function);
            callGraph.add(vertex);
        }

        // Step 2: Set edges based on functions' call sets!
        for (Map.Entry<Object, Vertex> entry : callGraph.getVertexEntrySet()) {
            Function function     = (Function) entry.getKey();
            Vertex funcVertex     = entry.getValue();
            Set<Function> callSet = function.getCalledFunctions(monitor);

            for (Function calledFunction : callSet) {
                Vertex callFuncVertex = callGraph.getVertex(calledFunction);
                if (callFuncVertex == null)
                    throw new RuntimeException("Failed to get correspodning vertex.");

                Edge edge = new Edge(funcVertex, callFuncVertex);
                callGraph.add(edge);
            }
        }

        return callGraph;
    }
}
