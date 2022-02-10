package dragonfang.propagators.properties;

import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.graphs.builders.CallGraphBuilder;
import dragonfang.graphs.builders.GraphBuilder;
import dragonfang.graphs.wrapper.ExtendedDirectGraphWrapper;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class PropagationPropertyTest extends AbstractDragonFangTest {

    @Test
    public void testChildCallGraphPropagationProperty() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        GraphBuilder graphBuilder = new CallGraphBuilder(program);
        ExtendedDirectGraphWrapper callGraphWarapper =
            new ExtendedDirectGraphWrapper(graphBuilder);
        callGraphWarapper.init(monitor);
        ChildCallGraphPropagationProperty childProperty =
            new ChildCallGraphPropagationProperty(callGraphWarapper);

        Function simpleFunction    = getSimpleFunction(builder);
        Set<Function> candidateSet = new HashSet<Function>();
        candidateSet.add(simpleFunction);

        Set<Function> resultSet =
            childProperty.getPropagatedFuncs(simpleFunction, candidateSet);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }

    @Test
    public void testParentCallGraphPropagationProperty() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        GraphBuilder graphBuilder = new CallGraphBuilder(program);
        ExtendedDirectGraphWrapper callGraphWarapper =
            new ExtendedDirectGraphWrapper(graphBuilder);
        callGraphWarapper.init(monitor);
        ParentCallGraphPropagationProperty parentProperty =
            new ParentCallGraphPropagationProperty(callGraphWarapper);

        Function simpleFunction    = getSimpleFunction(builder);
        Set<Function> candidateSet = new HashSet<Function>();
        candidateSet.add(simpleFunction);

        Set<Function> resultSet =
            parentProperty.getPropagatedFuncs(simpleFunction, candidateSet);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }

    @Test
    public void testBeforeAddressPropagationProperty() {

        BeforeAddressPropagationProperty beforeAdressProp =
            new BeforeAddressPropagationProperty();

        Function simpleFunction    = getSimpleFunction(builder);
        Set<Function> candidateSet = new HashSet<Function>();
        candidateSet.add(simpleFunction);

        Set<Function> resultSet =
            beforeAdressProp.getPropagatedFuncs(simpleFunction, candidateSet);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }

    @Test
    public void testAfterAddressPropagationProperty() {

        AfterAddressPropagationProperty afterAdressProp =
            new AfterAddressPropagationProperty();

        Function simpleFunction    = getSimpleFunction(builder);
        Set<Function> candidateSet = new HashSet<Function>();
        candidateSet.add(simpleFunction);

        Set<Function> resultSet =
            afterAdressProp.getPropagatedFuncs(simpleFunction, candidateSet);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }
}
