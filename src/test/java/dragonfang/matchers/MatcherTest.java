package dragonfang.matchers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dragonfang.AbstractDragonFangTest;
import dragonfang.counter.maps.InstrCountMap;
import dragonfang.counter.maps.LazyInstrCountMap;
import dragonfang.counters.PCodeInstrCounter;
import dragonfang.features.BBCountFeature;
import dragonfang.features.Feature;
import dragonfang.features.extractors.FeatureExtractor;
import dragonfang.features.extractors.FeatureListVectorExtractor;
import dragonfang.features.maps.FeatureMap;
import dragonfang.features.maps.LazyFeatureMap;
import dragonfang.features.metrics.CosineSimilarityMetric;
import dragonfang.features.metrics.FeatureSimilarityMetric;
import dragonfang.graphs.maps.ControlFlowGraphMap;
import dragonfang.graphs.maps.LazyControlFlowGraphMap;
import dragonfang.primes.InstrPrimeProductCalculator;
import dragonfang.primes.PCodePrimeProductCalculator;
import dragonfang.primes.maps.PrimeProductMap;
import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;

public class MatcherTest extends AbstractDragonFangTest {

    protected ProgramBuilder secBuilder;
    protected Program secProgram;

    @Before
    public void setUp() throws Exception {
        super.setUp();

        secBuilder = getProgramBuilderCopy();
        secProgram = secBuilder.getProgram();
    }

    @After
    public void tearDown() throws Exception {
        secBuilder.dispose();
    }

    private void
    checkCorrectMatch(Set<Match> matches, Function srcFunc, Function dstFunc) {

        assertEquals("Matches should be there!", matches.size(), 1);

        Match match = matches.iterator().next();
        assertSame("Matched source function should be correct.",
                   srcFunc,
                   match.getSourceFunction());
        assertSame("Matched source function should be correct.",
                   dstFunc,
                   match.getDestinationFunction());

        assertTrue("Must have high confidence", match.getConfidenceScore() > 0);
        assertTrue("Must have high similarity", match.getSimilarityScore() > 0);
    }

    @Test
    public void testPrimeProductMatcher() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        InstrPrimeProductCalculator primeProduct = new PCodePrimeProductCalculator();

        InstrCountMap countMap   = new LazyInstrCountMap(new PCodeInstrCounter());
        PrimeProductMap primeMap = new PrimeProductMap(primeProduct, countMap);

        InstrCountMap countMap2   = new LazyInstrCountMap(new PCodeInstrCounter());
        PrimeProductMap primeMap2 = new PrimeProductMap(primeProduct, countMap2);

        Function simpleFunction  = getSimpleFunction(builder);
        Function simpleFunction2 = getSimpleFunction(secBuilder);
        assertNotSame(simpleFunction, simpleFunction2);

        Set<Function> unmatchedSrcFuncSet = new HashSet<Function>();
        unmatchedSrcFuncSet.add(simpleFunction);
        Set<Function> unmatchedDstFuncSet = new HashSet<Function>();
        unmatchedDstFuncSet.add(simpleFunction2);

        PrimeProductMatcher primeProductMatcher =
            new PrimeProductMatcher(primeMap, primeMap2);
        Set<Match> matches = primeProductMatcher.doMatch(
            unmatchedSrcFuncSet, unmatchedDstFuncSet, monitor);

        checkCorrectMatch(matches, simpleFunction, simpleFunction2);
    }

    @Test
    public void testUniqueFeatureMatcher() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction  = getSimpleFunction(builder);
        Function simpleFunction2 = getSimpleFunction(secBuilder);
        assertNotSame(simpleFunction, simpleFunction2);

        ControlFlowGraphMap srcCFGMap = new LazyControlFlowGraphMap();
        List<Feature> srcFeatureList  = new ArrayList<Feature>();
        srcFeatureList.add(new BBCountFeature(srcCFGMap));
        FeatureExtractor srcFeatureExtractor =
            new FeatureListVectorExtractor(srcFeatureList);
        FeatureMap srcFeatureMap = new LazyFeatureMap(srcFeatureExtractor);

        ControlFlowGraphMap dstCFGMap = new LazyControlFlowGraphMap();
        List<Feature> dstFeatureList  = new ArrayList<Feature>();
        dstFeatureList.add(new BBCountFeature(dstCFGMap));
        FeatureExtractor dstFeatureExtractor =
            new FeatureListVectorExtractor(dstFeatureList);
        FeatureMap dstFeatureMap = new LazyFeatureMap(dstFeatureExtractor);

        Set<Function> unmatchedSrcFuncSet = new HashSet<Function>();
        unmatchedSrcFuncSet.add(simpleFunction);
        Set<Function> unmatchedDstFuncSet = new HashSet<Function>();
        unmatchedDstFuncSet.add(simpleFunction2);

        UniqueFeatureMatcher uniqueMatcher =
            new UniqueFeatureMatcher(srcFeatureMap, dstFeatureMap);
        Set<Match> matches =
            uniqueMatcher.doMatch(unmatchedSrcFuncSet, unmatchedDstFuncSet, monitor);

        checkCorrectMatch(matches, simpleFunction, simpleFunction2);
    }

    @Test
    public void testSimilarityFeatureMatcher() throws CancelledException {

        TaskMonitor monitor = new ConsoleTaskMonitor();

        Function simpleFunction  = getSimpleFunction(builder);
        Function simpleFunction2 = getSimpleFunction(secBuilder);
        assertNotSame(simpleFunction, simpleFunction2);

        ControlFlowGraphMap srcCFGMap = new LazyControlFlowGraphMap();
        List<Feature> srcFeatureList  = new ArrayList<Feature>();
        srcFeatureList.add(new BBCountFeature(srcCFGMap));
        FeatureExtractor srcFeatureExtractor =
            new FeatureListVectorExtractor(srcFeatureList);
        FeatureMap srcFeatureMap = new LazyFeatureMap(srcFeatureExtractor);

        ControlFlowGraphMap dstCFGMap = new LazyControlFlowGraphMap();
        List<Feature> dstFeatureList  = new ArrayList<Feature>();
        dstFeatureList.add(new BBCountFeature(dstCFGMap));
        FeatureExtractor dstFeatureExtractor =
            new FeatureListVectorExtractor(dstFeatureList);
        FeatureMap dstFeatureMap = new LazyFeatureMap(dstFeatureExtractor);

        Set<Function> unmatchedSrcFuncSet = new HashSet<Function>();
        unmatchedSrcFuncSet.add(simpleFunction);
        Set<Function> unmatchedDstFuncSet = new HashSet<Function>();
        unmatchedDstFuncSet.add(simpleFunction2);

        FeatureSimilarityMetric similarityMetric = new CosineSimilarityMetric();

        SimilarityFeatureMatcher similarityMatcher =
            new SimilarityFeatureMatcher(srcFeatureMap, dstFeatureMap, similarityMetric);
        Set<Match> matches =
            similarityMatcher.doMatch(unmatchedSrcFuncSet, unmatchedDstFuncSet, monitor);

        checkCorrectMatch(matches, simpleFunction, simpleFunction2);
    }
}
