package dragonfang.propagators.properties;

import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.entities.Entity;
import dragonfang.entities.FunctionEntity;
import dragonfang.entities.fetchers.EntityFetcher;
import dragonfang.entities.fetchers.FunctionEntityFetcher;
import dragonfang.graphs.builders.CallGraphBuilder;
import dragonfang.graphs.builders.GraphBuilder;
import dragonfang.graphs.wrapper.ExtendedDirectGraphWrapper;
import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class PropagationPropertyTest extends AbstractDragonFangTest
{

    @Test
    public void testChildCallGraphPropagationProperty() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        GraphBuilder graphBuilder = new CallGraphBuilder(program);
        ExtendedDirectGraphWrapper callGraphWarapper =
            new ExtendedDirectGraphWrapper(graphBuilder);
        callGraphWarapper.init(monitor);
        ChildCallGraphPropagationProperty childProperty =
            new ChildCallGraphPropagationProperty(callGraphWarapper);

        Function simpleFunction = getSimpleFunction(builder);
        Entity entity = new FunctionEntity(simpleFunction);

        Set<Entity> candidateSet = new HashSet<Entity>();
        candidateSet.add(entity);

        Set<Entity> resultSet =
            childProperty.getPropagatedEntities(entity, candidateSet, monitor);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }

    @Test
    public void testParentCallGraphPropagationProperty() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        GraphBuilder graphBuilder = new CallGraphBuilder(program);
        ExtendedDirectGraphWrapper callGraphWarapper =
            new ExtendedDirectGraphWrapper(graphBuilder);
        callGraphWarapper.init(monitor);
        ParentCallGraphPropagationProperty parentProperty =
            new ParentCallGraphPropagationProperty(callGraphWarapper);

        Function simpleFunction = getSimpleFunction(builder);
        Entity entity = new FunctionEntity(simpleFunction);

        Set<Entity> candidateSet = new HashSet<Entity>();
        candidateSet.add(entity);

        Set<Entity> resultSet =
            parentProperty.getPropagatedEntities(entity, candidateSet, monitor);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }

    @Test
    public void testBeforeAddressPropagationProperty() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        EntityFetcher entityFetcher = new FunctionEntityFetcher(program);
        BeforeAddressPropagationProperty beforeAdressProp =
            new BeforeAddressPropagationProperty(entityFetcher);

        Function simpleFunction = getSimpleFunction(builder);
        Entity entity = new FunctionEntity(simpleFunction);

        Set<Entity> candidateSet = new HashSet<Entity>();
        candidateSet.add(entity);

        Set<Entity> resultSet =
            beforeAdressProp.getPropagatedEntities(entity, candidateSet, monitor);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }

    @Test
    public void testAfterAddressPropagationProperty() throws CancelledException
    {
        TaskMonitor monitor = new ConsoleTaskMonitor();

        EntityFetcher entityFetcher = new FunctionEntityFetcher(program);
        AfterAddressPropagationProperty afterAdressProp =
            new AfterAddressPropagationProperty(entityFetcher);

        Function simpleFunction = getSimpleFunction(builder);
        Entity entity = new FunctionEntity(simpleFunction);

        Set<Entity> candidateSet = new HashSet<Entity>();
        candidateSet.add(entity);

        Set<Entity> resultSet =
            afterAdressProp.getPropagatedEntities(entity, candidateSet, monitor);
        assertTrue("Result set should be empty.", resultSet.isEmpty());
    }
}
