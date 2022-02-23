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

import dragonfang.entities.BasicBlockEntity;
import dragonfang.entities.Entity;
import dragonfang.graphs.ControlFlowGraph;
import dragonfang.graphs.ExtendedDirectGraph;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.Edge;
import ghidra.util.graph.Vertex;
import ghidra.util.task.TaskMonitor;

public class ControlFlowGraphBuilder implements GraphBuilder
{

    protected Function function;

    public ControlFlowGraphBuilder(Function function)
    {
        this.function = function;
    }

    @Override
    public ExtendedDirectGraph buildGraph(TaskMonitor monitor) throws CancelledException
    {
        ExtendedDirectGraph cfg = new ControlFlowGraph();
        BasicBlockModel basicBlockModel = new BasicBlockModel(function.getProgram());

        CodeBlockIterator codeBlockIterator =
            basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);

        // Step 1: Set vertices by iterating over basic blocks.
        while (codeBlockIterator.hasNext()) {
            CodeBlock codeBlock = codeBlockIterator.next();
            BasicBlockEntity entity =
                new BasicBlockEntity(codeBlock, function.getProgram());
            Vertex vertex = new Vertex(entity);
            cfg.add(vertex);
        }

        // Step 2: Set edges. To keep things simple, we only consider edges via direct
        // jumps, excluding calls and indirect jumps.
        for (Map.Entry<Object, Vertex> entry : cfg.getVertexEntrySet()) {
            BasicBlockEntity codeBlockEntity = (BasicBlockEntity) entry.getKey();
            Vertex bbVertex = entry.getValue();

            CodeBlockReferenceIterator destinations =
                codeBlockEntity.getCodeBlock().getDestinations(monitor);
            while (destinations.hasNext()) {
                CodeBlockReference reference = destinations.next();
                FlowType flowType = reference.getFlowType();
                if (flowType.isIndirect() || flowType.isCall()) {
                    continue; // Exclude these types of flows for simplicity.
                }

                Entity bbDsEntity = new BasicBlockEntity(reference.getDestinationBlock(),
                                                         function.getProgram());
                Vertex bbDstVertex = cfg.getVertex(bbDsEntity);
                if (bbDstVertex == null)
                    throw new RuntimeException("Failed to get correspodning vertex.");

                Edge edge = new Edge(bbVertex, bbDstVertex);
                cfg.add(edge);
            }
        }

        return cfg;
    }
}
