package dragonfang.graphs.wrapper;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.graphs.ExtendedDirectGraph;
import dragonfang.graphs.ExtendedDirectGraph.ExtDirectGraphType;
import dragonfang.graphs.builders.CallGraphBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class ExtendedDirectGraphWrapperTest extends AbstractDragonFangTest {

    @Test
    public void testExtendedDirectGraphWrapper() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        CallGraphBuilder callGraphBuilder = new CallGraphBuilder(program);
        ExtendedDirectGraphWrapper wrapper =
            new ExtendedDirectGraphWrapper(callGraphBuilder);
        wrapper.init(monitor);

        ExtendedDirectGraph callGraph = wrapper.getGraph();

        ExtDirectGraphType type = callGraph.getType();
        assertEquals(
            "Graph should be type Call Graph", ExtDirectGraphType.CALL_GRAPH, type);

        assertEquals("Number of edges should be zero", 0, callGraph.numEdges());
        assertEquals("Number of vertices should be 1", 1, callGraph.numVertices());
    }
}
