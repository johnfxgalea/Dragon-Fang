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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.graphs.ExtendedDirectGraph;
import dragonfang.graphs.ExtendedDirectGraph.ExtDirectGraphType;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.Vertex;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class GraphBuilderTest extends AbstractDragonFangTest {

	@Test
	public void testCallGraphBuilder() throws CancelledException {

		TaskMonitor monitor = new ConsoleTaskMonitor();

		CallGraphBuilder callGraphBuilder = new CallGraphBuilder(program);
		ExtendedDirectGraph callGraph = callGraphBuilder.buildGraph(monitor);

		ExtDirectGraphType type = callGraph.getType();
		assertEquals("Graph should be type Call Graph", ExtDirectGraphType.CALL_GRAPH, type);

		assertEquals("Number of edges should be zero", 0, callGraph.numEdges());
		assertEquals("Number of vertices should be 1", 1, callGraph.numVertices());

		Function simpleFunction = getSimpleFunction(builder);
		Vertex vertex = callGraph.getVertexArray()[0];
		Vertex obtainedVertex = callGraph.getVertex(simpleFunction);
		assertTrue("Vertexes should match", vertex.equals(obtainedVertex));
	}

	@Test
	public void testCFGBuilder() throws CancelledException {

		TaskMonitor monitor = new ConsoleTaskMonitor();

		Function simpleFunction = getSimpleFunction(builder);

		ControlFlowGraphBuilder cfgBuilder = new ControlFlowGraphBuilder(simpleFunction);
		ExtendedDirectGraph cfg = cfgBuilder.buildGraph(monitor);

		ExtDirectGraphType type = cfg.getType();
		assertEquals("Graph should be type CFG", ExtDirectGraphType.CONTROL_FLOW_GRAPH, type);

		assertEquals("Number of edges should be zero", 0, cfg.numEdges());
		assertEquals("Number of vertices should be 1", 1, cfg.numVertices());

		BasicBlockModel basicBlockModel = new BasicBlockModel(program);
		CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocksContaining(simpleFunction.getBody(),
				monitor);
		CodeBlock codeBlock = codeBlockIterator.next();

		Vertex vertex = cfg.getVertexArray()[0];
		Vertex obtainedVertex = cfg.getVertex(codeBlock);
		assertTrue("Vertexes should match", vertex.equals(obtainedVertex));
	}
}
