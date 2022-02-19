package dragonfang.propagators;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.HashSet;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counter.maps.LazyInstrCountMap;
import dragonfang.counters.PCodeInstrCounter;
import dragonfang.graphs.builders.CallGraphBuilder;
import dragonfang.graphs.builders.GraphBuilder;
import dragonfang.graphs.wrapper.ExtendedDirectGraphWrapper;
import dragonfang.matchers.Match;
import dragonfang.matchers.PrimeProductMatcher;
import dragonfang.primes.InstrPrimeProductCalculator;
import dragonfang.primes.PCodePrimeProductCalculator;
import dragonfang.primes.maps.PrimeProductMap;
import dragonfang.propagators.properties.ChildCallGraphPropagationProperty;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class PropagatorTest extends AbstractDragonFangTest
{

    protected ProgramBuilder secBuilder;
    protected Program secProgram;

    @Before
    public void setUp() throws Exception
    {
        super.setUp();

        secBuilder = getProgramBuilderCopy();
        secProgram = secBuilder.getProgram();
    }

    @After
    public void tearDown() throws Exception
    {
        secBuilder.dispose();
    }

    @Test
    public void testPropagator() throws CancelledException
    {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        InstrPrimeProductCalculator primeProduct = new PCodePrimeProductCalculator();

        InstrCountMap countMap = new LazyInstrCountMap(new PCodeInstrCounter());
        PrimeProductMap primeMap = new PrimeProductMap(primeProduct, countMap);

        InstrCountMap countMap2 = new LazyInstrCountMap(new PCodeInstrCounter());
        PrimeProductMap primeMap2 = new PrimeProductMap(primeProduct, countMap2);

        Function simpleFunction = getSimpleFunction(builder);
        Function simpleFunction2 = getSimpleFunction(secBuilder);
        assertNotSame(simpleFunction, simpleFunction2);

        Set<Function> unmatchedSrcFuncSet = new HashSet<Function>();
        unmatchedSrcFuncSet.add(simpleFunction);
        Set<Function> unmatchedDstFuncSet = new HashSet<Function>();
        unmatchedDstFuncSet.add(simpleFunction2);

        PrimeProductMatcher primeProductMatcher =
            new PrimeProductMatcher(primeMap, primeMap2);
        Set<Match> matches = primeProductMatcher.doMatch(unmatchedSrcFuncSet,
                                                         unmatchedDstFuncSet, monitor);

        assertEquals("Matches should be there!", matches.size(), 1);

        Match match = matches.iterator().next();

        GraphBuilder srcBuilder = new CallGraphBuilder(program);
        ExtendedDirectGraphWrapper srcCallGraphWarapper =
            new ExtendedDirectGraphWrapper(srcBuilder);
        srcCallGraphWarapper.init(monitor);
        ChildCallGraphPropagationProperty srcChildProperty =
            new ChildCallGraphPropagationProperty(srcCallGraphWarapper);

        GraphBuilder dstBuilder = new CallGraphBuilder(secProgram);
        ExtendedDirectGraphWrapper dstCallGraphWarapper =
            new ExtendedDirectGraphWrapper(dstBuilder);
        dstCallGraphWarapper.init(monitor);
        ChildCallGraphPropagationProperty dstChildProperty =
            new ChildCallGraphPropagationProperty(dstCallGraphWarapper);

        PropertyBasedPropagator propagator =
            new PropertyBasedPropagator(srcChildProperty, dstChildProperty);
        Set<Match> propMatches =
            propagator.propagate(primeProductMatcher, match, new HashSet<Function>(),
                                 new HashSet<Function>(), monitor);

        assertTrue("No new matches", propMatches.isEmpty());
    }
}
