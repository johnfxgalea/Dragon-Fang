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

package dragonfang.graphs;

import static org.junit.Assert.*;
import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.graphs.ExtendedDirectGraph.ExtDirectGraphType;

public class ExtendedDirectGraphTest extends AbstractDragonFangTest {

	@Test
	public void testControlFlowGraph() {

		ControlFlowGraph cfg = new ControlFlowGraph();
		ExtDirectGraphType type = cfg.getType();
		assertEquals("Graph should be type CFG", ExtDirectGraphType.CONTROL_FLOW_GRAPH, type);
	}

	@Test
	public void testCallGraph() {

		CallGraph cg = new CallGraph();
		ExtDirectGraphType type = cg.getType();
		assertEquals("Graph should be type Call Graph", ExtDirectGraphType.CALL_GRAPH, type);		
	}
}
