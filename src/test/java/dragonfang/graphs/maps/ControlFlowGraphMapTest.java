package dragonfang.graphs.maps;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.graphs.ExtendedDirectGraph;
import dragonfang.graphs.ExtendedDirectGraph.ExtDirectGraphType;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class ControlFlowGraphMapTest extends AbstractDragonFangTest {

	@Test
	public void testControlFlowGraphMap() throws CancelledException {

		TaskMonitor monitor = new ConsoleTaskMonitor();

		ControlFlowGraphMap map = new LazyControlFlowGraphMap();

		Function simpleFunction = getSimpleFunction(builder);
		ExtendedDirectGraph cfg = map.getControlFlowGraph(simpleFunction, monitor);

		ExtDirectGraphType type = cfg.getType();
		assertEquals("Graph should be type CFG", ExtDirectGraphType.CONTROL_FLOW_GRAPH, type);

		assertEquals("Number of edges should be zero", 0, cfg.numEdges());
		assertEquals("Number of vertices should be 1", 1, cfg.numVertices());
	}
}
