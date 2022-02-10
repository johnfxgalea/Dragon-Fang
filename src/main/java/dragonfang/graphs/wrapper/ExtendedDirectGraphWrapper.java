package dragonfang.graphs.wrapper;

import dragonfang.graphs.ExtendedDirectGraph;
import dragonfang.graphs.builders.GraphBuilder;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class ExtendedDirectGraphWrapper {

    private GraphBuilder builder;
    private ExtendedDirectGraph graph;

    public ExtendedDirectGraphWrapper(GraphBuilder builder) {
        this.builder = builder;
    }

    public void init(TaskMonitor monitor) throws CancelledException {

        graph = builder.buildGraph(monitor);
    }

    public ExtendedDirectGraph getGraph() {
        if (graph == null)
            throw new RuntimeException("Graph not initialised!");

        return graph;
    }
}
